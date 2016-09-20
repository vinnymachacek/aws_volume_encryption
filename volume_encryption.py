#! /usr/bin/env python

"""
Overview:
    Take unencrypted root volume and encrypt it for EC2.
Arguments:
  -h, --help            show this help message and exit
  -i INSTANCE, --instance INSTANCE
                        Instance to encrypt volume on.
  -key CUSTOMER_MASTER_KEY, --customer_master_key CUSTOMER_MASTER_KEY
                        Customer master key
  -p PROFILE, --profile PROFILE
                        Profile to use
  -c, --cleanup_intermediate_snapshots
                        Cleanup resources created while converting volume
  -d, --delete_original_volumes
                        Delete original Volume
Conditions:
    Return if volume already encrypted
    Use named profiles from credentials file
"""

import sys
import boto3
import botocore
import argparse


def main(argv):
    parser = argparse.ArgumentParser(description='Encrypts EC2 root volume.')
    parser.add_argument('-i', '--instance',
                        help='Instance to encrypt volume on.', required=False)
    parser.add_argument('-key', '--customer_master_key',
                        help='Customer master key', required=False)
    parser.add_argument('-p', '--profile',
                        help='Profile to use', required=False)
    parser.add_argument('-c', '--cleanup_intermediate_snapshots',
                        help='Cleanup resources created while converting volume', required=False, action='store_true')
    parser.add_argument('-d', '--delete_original_volumes',
                        help='Delete original Volume', required=False, action='store_true')
    args = parser.parse_args()

    """ Set up AWS Session + Client + Resources + Waiters """
    if args.profile:
        # Create custom session
        print('Using profile {}'.format(args.profile))
        session = boto3.session.Session(profile_name=args.profile)
    else:
        # Use default session
        session = boto3.session.Session()

    # Get CMK
    customer_master_key = args.customer_master_key

    client = session.client('ec2')
    ec2 = session.resource('ec2')

    waiter_instance_exists = client.get_waiter('instance_exists')
    waiter_instance_stopped = client.get_waiter('instance_stopped')
    waiter_instance_running = client.get_waiter('instance_running')
    waiter_snapshot_complete = client.get_waiter('snapshot_completed')
    waiter_volume_available = client.get_waiter('volume_available')

    """ Check instance exists """
    if args.instance:
        instances = ec2.instances.filter(InstanceIds=[arg.instance_id])
    else:
        instances = ec2.instances.all()
    for instance in instances:
        instance_id = instance.id
        print(instance.id)
        try:
            waiter_instance_exists.wait(
                InstanceIds=[
                    instance_id,
                ]
            )
        except botocore.exceptions.WaiterError as e:
            sys.exit('ERROR: {}'.format(e))

        """ Get volume and exit if already encrypted """
        volumes = [v for v in ec2.volumes.filter(Filters=[{"Name":"attachment.instance-id","Values":[instance_id]},{"Name":"encrypted", "Values":[
        "false"] }])]
        if not volumes:
            continue
        """ Step 1: Prepare instance """
        print('---Preparing instance')
        
        # Exit if instance is pending, shutting-down, or terminated
        instance_exit_states = [0, 32, 48]
        if instance.state['Code'] in instance_exit_states:
            sys.exit(
                'ERROR: Instance is {} please make sure this instance is active.'
                .format(instance.state['Name'])
            )

        # Validate successful shutdown if it is running or stopping
        if instance.state['Code'] is 16:
            instance.stop()

        # Set the max_attempts for this waiter (default 40)
        waiter_instance_stopped.config.max_attempts = 40

        try:
            waiter_instance_stopped.wait(
                InstanceIds=[
                    instance_id,
                ]
            )
        except botocore.exceptions.WaiterError as e:
            sys.exit('ERROR: {}'.format(e))

        for volume in volumes:
            # Save original mappings to persist to new volume
            original_mappings = volume.attachments

            """ Step 2: Take snapshot of volume """
            print('---Create snapshot of volume ({})'.format(volume.volume_id))
            snapshot = ec2.create_snapshot(
                VolumeId=volume.volume_id,
                Description='Snapshot of volume ({})'.format(volume.volume_id),
            )

            try:
                waiter_snapshot_complete.wait(
                    SnapshotIds=[
                        snapshot.id,
                    ]
                )
            except botocore.exceptions.WaiterError as e:
                snapshot.delete()
                sys.exit('ERROR: {}'.format(e))

            """ Step 3: Create encrypted volume """
            print('---Create encrypted copy of snapshot')
            if customer_master_key:
                # Use custom key
                snapshot_encrypted_dict = snapshot.copy(
                    SourceRegion=session.region_name,
                    Description='Encrypted copy of snapshot #{}'
                                .format(snapshot.id),
                    KmsKeyId=customer_master_key,
                    Encrypted=True,
                )
            else:
                # Use default key
                snapshot_encrypted_dict = snapshot.copy(
                    SourceRegion=session.region_name,
                    Description='Encrypted copy of snapshot ({})'
                                .format(snapshot.id),
                    Encrypted=True,
                )

            snapshot_encrypted = ec2.Snapshot(snapshot_encrypted_dict['SnapshotId'])

            try:
                waiter_snapshot_complete.wait(
                    SnapshotIds=[
                        snapshot_encrypted.id,
                    ],
                )
            except botocore.exceptions.WaiterError as e:
                snapshot.delete()
                snapshot_encrypted.delete()
                sys.exit('ERROR: {}'.format(e))

            print('---Create encrypted volume from snapshot')
            volume_encrypted = ec2.create_volume(
                SnapshotId=snapshot_encrypted.id,
                AvailabilityZone=instance.placement['AvailabilityZone']
            )

            """ Step 4: Detach current root volume """
            print('---Deatch volume {}'.format(volume.volume_id))
            instance.detach_volume(
                VolumeId=volume.volume_id,
                Device=original_mappings["Device"],
            )

            """ Step 5: Attach current root volume """
            print('---Attach volume {}'.format(volume_encrypted.id))
            try:
                waiter_volume_available.wait(
                    VolumeIds=[
                        volume_encrypted.id,
                    ],
                )
            except botocore.exceptions.WaiterError as e:
                snapshot.delete()
                snapshot_encrypted.delete()
                volume_encrypted.delete()
                sys.exit('ERROR: {}'.format(e))

            instance.attach_volume(
                VolumeId=volume_encrypted.id,
                Device=original_mappings["Device"]
            )

            """ Step 6: Restart instance """
            # Modify instance attributes
            instance.modify_attribute(
                BlockDeviceMappings=[
                    {
                        'DeviceName': original_mappings["Device"],
                        'Ebs': {
                            'DeleteOnTermination':
                            original_mappings['DeleteOnTermination'],
                        },
                    },
                ],
            )

            """ Step 7: Clean up """
            #Safety First! Let's make cleanup a explicit option for the use
            if args.cleanup_intermediate_snapshots:
                print('---Clean up intermediate snapshots')
                # Delete snapshots
                print('Deleting intermediate snapshots')
                snapshot.delete()
                snapshot_encrypted.delete()
            if args.delete_original_volume:
                print('Deleting original volume')
                volume.delete()
            print('Encryption finished')
        print('---Restart instance')
        instance.start()

        try:
            waiter_instance_running.wait(
                InstanceIds=[
                    instance_id,
                ]
            )
        except botocore.exceptions.WaiterError as e:
            sys.exit('ERROR: {}'.format(e))

if __name__ == "__main__":
    main(sys.argv[1:])
