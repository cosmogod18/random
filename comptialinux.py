
# This file helps to prepare for Comptia-Linux+ certification :)
# GOOD LUCK M8! 




1. Distributions 
	1.1 Main distributions:
			RedHat(RHEL)		Ubuntu(based on Debian)		SUSE	
			CentOS			Mint				Oracle(Oracle enterprise linux)
			Fedora


2. Using Essential Tools
	2.1 Man Page (Get help, something like "command --help", just more advanced)
	        Man pages common elements:
			# Items between [brackets] are optional
			# If you see {a|b} you must choose
			# And ... means you may have more of the preceding item
		Man pages have sections:
			# 1 is for end-user commands
			# 8 is for administrator (root) commands
			# 5 is for configuration files
                Man page examples:
                        # man lvcreate 5
                        # man -k lvcreate
                Update man pages:
                        # mandb


3. Essential File Management Tools
        3.1 Linux File System Hierarchy
                /---|
                    /bin -> /usr/bin            #Binary files
                    /boot                       #Boot Loaders, Kernels 
                    /dev                        #Devices
                    /etc                        #Configuration Files
                    /home                       #User's Home Directories
                    /lib -> /usr/lib            
                    /lib64 -> /usr/lib64
                    /media                      #Mounts like USB
                    /mnt                        #Mounts like USB
                    /opt                        #Applications
                    /proc                       #Interface to Linux Kernel, get info about process
                    /root                       #Root's Home Directory
                    /run                        #Temp directory for processes that temporary needs to write files
                    /sbin -> /usr/sbin          #User Binary files
                    /srv                        #Typicaly Empty | Service Directory 
                    /sys                        #Hardware Information
                    /tmp                        #Temp Files 
                    /usr                        #Like Program Files in Windows
                    /var                        #Dynamically created files by OS, Logs and Etc
        
        3.2 Wildcards | Globbing 
                *       - Everything
                ?       - Single char 
                [a-z]   - Range 
                #You can combine them
                    [a-b]?h*
        
        3.3 Hard and Symbolic (soft) links - SHORTCUTS:
                Hard link limitations:
                    # No cross-device (must be on same partition)
                    # No directories

                Examples:
                    #Create hard link
                        ln /etc/hosts /home/hosts
                    #Create Symbolic (soft) link
                        ln -s /etc/hosts /home/hosts
        
        3.4 Finding files with find:
                Examples:
                    find / -name "hosts"                                              # Find all files "hosts" in / 
                    mkdir /root/test; find / -user Username -exec cp {} /root/test \; # creates /root/test dir and Copy all found files into /root/test dir
                    find / -size +100M 2>/dev/null                                    # finds all files bigger than 100MB and redirect errors to /dev/null 
                    find / -type f -size +100M                                        # find files bigger than 100MB
                    # Its possible to use multiple -exec statments.
                    find / -exec grep -l something {} \; -exec cp {} /root/test \;
                    find / -name '*' -type f | xargs grep "something" 
        
        3.5 Archiving Files with tar
                tar -cvf home.tar /home /etc        # Compres home and etc contents into home.tar 33M
                tar -xvf home.tar -C /destination   # Extract home.tar 
                tar -tvf home.tar                   # Check content of home.tar
                tar -cvfz home.tgz /home /etc       # Compress home and etc contents into home.tgz 8M
                tar -cvfj home.tbz /home /etc       # Compress home and etc into home.tbz 7.8M (little bit better compression)

        3.6 Managing File Compressions
                gzip - most common compression utility (oldest) 
                bzip2 - alternative utility  
                zip - can be used as well (very compatible)
                xz - recent addition to the wide range of compression tools
                man -k cpio
                Examples:
                        # Generate 1G file: dd if=/dev/zero of=bigfile bs=1M count=1024
                        gzip bigfile                - 104M : gunzip file        #uncompres
                        bzip2 bigfile               - 1M   : bzip2 -d file      #uncompres
                        zip bigfile.zip bigfile     - 1M   : uzip file          #uncompres
                        xz bigfile                         : unxz file          #ncompress

4. Connecting to a Server
        4.1 Creating a simple sudo Configuration
                vim /etc/sudoers.d/testuser
                usermod -aG sudo testuser           # Adds user to sudoers 
                testuser ALL=/bin/passwd            # Allows user only change password


5. Working with the Bash Shell
        5.1 I/O Redirection 
                # <     - Input
                # >     - Output/overwrite
                # >>    - Append to a file
                # 2>    - Redirect error 
                # &>    - Standard and error redirect 

        5.2 Bash Features
                Create alias:
                    vim /etc/profile or ~/.bashrc

        5.3 Bash Startup Files:
                /etc/environment    # Contains a list of variables and is the first file that is processed while starting bash 
                /etc/profile        # Executed while users login
                /etc/profile.d      # Used as snapin directory that contains additional configuration
                ~/.bash_profile     # Can be used as a user-specific version
                ~/.bash_logout      # Processed when a user logs out
                /etc/bashrc         # Processed every time a subshell is started
                ~/.bashrc           # User-specific file may be used


6. User and Group Management and Permissions
        6.1 Default for New Users
                /etc/login.defs         # Used as the default configuration file 
                /etc/skel               # Default contents in User's home directory
                /etc/default/useradd    # Settings for useradd
                useradd -D              # Shows defaults
        
        6.2 Managing Password Properties
                echo "password" | passwd --stdin USER                                           # Centos | Change USER password from pipe
                echo "linda:password" | chpasswd                                                # Ubuntu 
                for i in ana anouk linda lisa; do echo password | passwd --stdin $i; done       # Fancy way
                chage USER                                                                      # Set password properties

        6.3 Configuration files
                /etc/group          # Shows groups and members
                /etc/gshadow        # Not used any more (set password for groups)
                /etc/shadow         # Shows encrypted passwords
                /etc/passwd         # Shows UID\GUID, homedir, shell
        
        6.4 Session Management
                w or who                                # shows who is currently logged in
                loginctl                                # allows for current session management
                loginctl list-sessions                    
                loginctl session-status <session-id>
                loginctl show-session <id>
                loginctl show-user <username>
                loginctl terminate-session <session-id>
        
7. Permission Management
        7.1 Basic Permissions
                                    FILE        DIRECTORY
                    READ(4)         open        list
                    WRITE(2)        modify      create/delete
                    EXECUTE(1)      run         CD
        
        7.2 Advanced Linux Permissions 
            
                                    FILE                    DIRECTORY   
                    SUID(4)         run as owner                -                                   # almost never used by admins, only by programs
                    SGID(2)         run as group owner      inherit directory group owner           # chmod g+s /data/directory/ useful, for shared env.
                    Sticky(1)       -                       only delete if owner                    # chmod +t /data/directory/ | deleting possible if u are owner of file or directory 
                    #chmod [4]774 - 4 shows mask
        
        7.3 Managing umask
                The umask is a shell settings that defines a mask that will be subtracted from the default permissions
                Default permissions on directories are 777
                Default permissions on files are 666
                    # umask 022 will set default permissions on files to 644
                    # umask 027 will set default permissions on directories to 750
                    # grep umask /etc/* | usually in /etc/profile, bashrc 
               

8. Storage Management Essentials
        8.1 Linux Storage Solutions
                Devices             |
                Disk                |------ /dev/sda ---> Partitions /dev/sda1, /dev/sda2  -->  LVM(Like partition in the partition) 
                SAN - iscsi - fibre |

                
                MBR (older,default on centos7, 4 primary partitions)                                GPT (newer, 128 partitions)
                lsblk/cat /prtoc/partitions #check blocks                                           gdisk /dev/sda
                fdisk /dev/sda              #modify disk/create/delete                              

        8.2 Creating Filesystems
                mkfs.ext4 /dev/sda1 (there is more.. tab tab)          #create  ext4 filesystem on /dev/sda1

        8.3 Mounting Filesystems
                mount /dev/sda1 /mnt-point  #temp mount, if needs permanent /etc/fstab
                umount /mnt-point           #unmount mnt-point if bussy check 'lsof /mnt-point'


9. Managing Networking
        9.1 IPv6 basic
                ::1/128     localhost
                ::          0.0.0.0
                ::/0        default route
                2000::/3    global unicast address
                fd00::/8    unique local address (routable, private addresses)
                fe80::/64   link-local address (non routable)
                ff00::/8    multicast
                #To change computer resolve priority - change /etc/nsswitch.conf hosts line.

10. Managing Time
        10.1 Linux time
                time -s 14:00                               # set time manualy
                timedatectl list-timezones
                timedatectl set-timezone Europe/Vilnius
        
        10.2 NTP 
                timedatectl status                          #Check if using 
                timedatectl set-ntp true
                ntpdate ntp.server.lt


11. Working with Systemd
        11.1 Understanding Systemd
                Systemd is the manager of everything: BOOT ----> Kernel ----> SystemD
                The items that are managed by systemd are called units
                Default units are in /usr/lib/systemd/system, custom units are in /etc/systemd (depends on distribution)

        11.2 Managing SystemD services (/etc/systemd/system wins vs /lib/systemd/system)
                systemctl -t help               # Shows unit type
                systemctl list-unit-files       # Lists all installed units
                systemctl list-units            # Lists active units
       
               
        11.3 Service Configuration
                systemctl cat name.service      # Reads current unit configuration 
                systemctl show [name.service]   # Shows all available configuration parametres
                systemctl edit name.service     # Edit service configuration
                systemctl daemon-reload         # After editing service configuration reload systemd

        11.4 Understand Targes
                A target is a group of services
                Some targets are isolatable , which means that you can use them as a state your system should be in
                # emergency.target       - for troubleshooting 
                # rescue.target          - for troubleshooting
                # multi-user.traget      - loads all non graphical targets
                # graphical.target       - loads fully graphical targets, for examples if u wanna boot non graphical: systemctl isolate multi-user.target
                systemctl list-dependencies name.target         # To see the contents and dependencies of a systemd target
                
        11.5 Managing Targets
                systemctl isolate name.target
                systemctl get-default
                systemctl set-default name.target


12. Process Management
        12.1 Understanding Linux Processses and Jobs
                init  = systemd              
                        |--http
                        |--sshd
                            |--bash
                                |--echo
            
                if u kill parent "sshd" process , kids are automaticaly killed "bash" , "echo"
                
                jobs = processes that running in a current shell 
                
        12.2 Managing interactive shell jobs
                dd if=/dev/zero of=/dev/null &              # Start job in a background
                jobs                                        # List all active jobs
                fg                                          # Change to foreground

        12.3 TOP
                top -u User         # Show for specific user top
                f                   # Show Fields
                r                   # Renice process, higher nice less cpu -20 ~ 20


        12.4 Process Priority
                renice -n 5 PID      # on working process
                nice -n -20 script   # on new process

        12.5 SIGNALS
                man 7 signal
                kill -9 PID         # Brutal way to kill process, risk with coruptions on writing/saving data and etc
                default 15          # Soft kill 
                killall PROCESS     # kill all process 


13. Managing software
        13.1 Managing Libraries
                ldd /usr/bin/passwd         # List of libs that used by passwd

    
        13.2 Software Managers
                YUM:
                    /etc/yum.repos.d
                    yum repolist                        # Shows repositories
                    yum list installed [package]        # List all installed packages
                    yum remove package                  # Remove package and all dependent packages
                    yum group list                      # Get groups that exist on ur system
                    yum group install
                    yum provides                        # Like search, but more deeply
                    yum history                         # Shows history, after that u can use yum history undo [number] 
                    yumdownloader package               # Downloads package.rpm

                APT:
                    /etc/apt/source.list
                    apt remove package                  # Removes package
                    apt autoremove                      # Removes all unnecessary packages (dependencies)

                RPM:
                    rpm -qf file                        # Will tell you which package a file is from
                    rpm -ql package                     # Queries the database to list package contents
                    rpm -qpc package.rpm                # List configuration files in a downloaded package file
                    rpm -qp --scripts package.rpm       # Shows scripts that may be present in a package


14. Scheduling Tasks
        14.1 Systemd timers
                /usr/lib/systemd/system/*.timer         # Timer should have service file too
                man systemd.timer


15. Reading Log Files
        15.1 Linux Logging
                    
                    journalctl                                                      # Shows complete journal
                    journalctl -u <unit>                                            # Shows information about specific unit
                    journalctl --dmesg                                              # Shows kernel messsages
                    journalctl -u crond --since yesterday --until 9:00 -p info      # Filters


16. Advanced User Settings
        16.1 ACL
                    setfacl -R -m g:groupname:rx /destination/dir               # create acl for current files, -R recursive, -m - modify, g-group:groupname:rights /destination
                    setfacl -m d:g:groupname:rx /destination/dir                # create acl for new files
                    setfacl -x g:groupname /destination/fileORdir               # remove acl

        16.2 Filesystem Quota (Limiting the number of files a user or group can create, not file size)
                    Quota soft limits are limits that trigger a timer, once the timer has been reached, the hard limit becomes effective, when usage drops below the soft limit, the timer is disabled.
                    Quota hard limits are absolute and set a strict limitations to the number of files or inodes a user can create.

                    Enable quota on EXT4 filesystem:
                        1. yum install quota
                        2. vim /etc/fstab, set usrquota and grpquota mount options
                        3. Run quotacheck -mavug - creates the aquota.user and aquota.group files
                        4. Monitor current quota usage for a user: quota -vu USER
                        5. Ensure the quota automatically switches on: quotaon -a
                        6. Edit user quota, using edquota -u USER or edquota -g GROUP
                        7. repquota -aug scan quota settings on all volumes

                    XFS support three types of quota:
                        1. User quota: limits for specific users
                        2. Group quota: limites for specific groups
                        3. Project quota: limits on available disk space in specific directories
                        When working with project quota you need 2 files:
                                /etc/projects contains the project ID and the name of the directory to which the quota applies.
                                /etc/projid contains the project name and the project ID
                                Project ID as well as project name are random strings that an admin can set
                                To enable XFS quota u have to use rootflags=uquota or rootflags=pquota as boot parameter to enable quota on the root FS
                                To enable user quota:
                                    mount -o uquota /dev/sdb1 /home
                                    xfs_quota -x -c 'limit bsoft=5m bhard=6m USER' /home  (m stands for MB, g stands for GB)
                                    xfs_quota -x -c report /home
                                
                                To enable project quota:
                                    mount -o pquota /dev/sdb1 /mount-point
                                    echo 11:/mount-point >> /etc/projects
                                    echo testquota:11 >> /etc/projid
                                    xfs_quota -x -c 'project -s testquota'
                                    xfs_quota -x -c "print" /mount-point
                                    xfs_quota -x -c "report -pbih" /mount-point
                                    xfs_quota -x -c 'limit -p bsoft=100m bhard=200m testquota' /mount-point
                                    xfs_quota -x -c "report -pbih" /mount-point
                                    test dd if=/dev/zero of=/mount-point/bigfile bs=1M count=300

17. Managing Internationalization
        17.1 Managing Timezones
                tzselecct   # Select Zone

        17.2 Managing Time
                Synchronize system time to hwtime:
                    hwclock -w
        
        17.3 Managing Languages
                For user in profile change LANG=
                localectl status                # shows current settings
                localectl --help
                
        17.4 Managing Code Tables
                LANG=LANG.CODE          # LANG=fr_FR.UTF-8


18. Storage Management
        18.1  Basic Hardware Management
                Linux uses kernel modules to work with specific device types(SATA,SCSI, MONITOR, PCI, PRINTERS, USB and etc.)
                Kernel modules are included in the initramfs, or can be loaded on demand.
                Automatic on-demand devices initialization is done by systemd-udevd
                Manual devices loading can be done using modprobe
                Interface with devices many (not all) devices have a devices node file in /dev
                Also, Hardware related parameters are stored in /sys and its subdirectories

        18.2 Lising Device information
                lsdev           # list devices
                lsusb           # list usb devices
                lspci           # list pci devices
                lsblk           # list block devices
                abrt            # aditional devices information

        18.3 Managing Kernel Modules
                First, kernel modules are loaded through initramfs while booting
                The initramfs is system specific and automatically generated at the end of the instaltion
                While booting, systemd starts systemd-udevd to manage on-demand loading of kernel modules
                Manual loading can be done using modprobe and insmod(deprecated)
                To get module parameters use 'modinfo module'
                Use 'modprobe -r' to remove manually-loaded kernel modules from memory
                Module dependencies are automatically generated through 'depmod'
                Specify parameters in /etc/modprobe.conf and /etc/modprobe.d
                lsmod                   # Lists all currently loaded kernel modules
                modprobe modulename     # Loads module
                modprobe -r modulename  # Removes module

        18.4 Understanding systemd-udevd
                When alerted by the Linux kernel, systemd-edevd will initialize new devices automaticaly
                Use 'udevadm monitor' to trace the procedure of device initialization
                To get detailed information about devices, use :
                    udevadm info --name=/dev/node, as in udevadm info --name=/dev/sda
        
        18.5 Managing Udev Rules
                While initializing devices, udev rules can be used
                The rules can set specific device properties
                Default rules are in '/usr/lib/udev/rules.d' (lowerst priority)
                Administrator created rules are in '/etc/udev/rules.d' (highest priority)
                #For exampele u can create rule, that PC accepts only one brand USB and reject all anothers.
                Dynamicaly generated (volatile) rules are written to '/run/udev/rules.d'

        18.6 /dev/ /sys /proc Usage
                The Linux kernel uses pseudo filesystems - these exist in memory only and not n disk
                /proc           # is for kernel runtime information and tunables
                /sys            # is used for hardware related information
                /dev            # is used to create devices nodes
                
        18.7 Priting
                cupsd           # Sends jobs from the printer spool directory to the allocated printer
                lpr             # Utility can be used to print files from the Linux cli
                lpq             # Gives an overview of current printer status

19. Managing Partitions
        19.1 MBR vs GPT
                MBR(master boot record)msdos                                                            GPT(Guid Partition Table)
                4 primary partitions are supported                                                      Larger are to store up to 128 partitions
                To address more partitions, extended and logical partitions are needed                  No more need for extended partitions
                A maximum of 2 TB can be addressed                                                      Required on system that work with UEFI
                fdisk is recommended utility to create MBR partitions                                   parted or gdisk
                LVM parition type 8e                                                                    LVM partition type 8e00

        19.2 Storage Device Names
                UUID        # Created when the file system is created   
                Labels      # Optional property of file systems
                /dev/disk   # Automaticaly generated by systemd-udevd
                
                mkfs.xfs(ext4) -L labelName /dev/sda1

        19.3 Raid configurations:
                RAID 0 : Striping
                RAID 1 : Mirroring
                RAID 5 : Striping with distribured parity
                RAID 6 : Striping with dual distributed parity
                RAID 10 : Mirrored and striped

                Steps to create RAID
                    fdisk /dev/sdb; fdisk /dev/sdc; use type RAID
                    mdadm --create /dev/md0 --level=1 --raid-disks=2 /dev/sdb /dev/sdc
                    mkfs.ext4 /dev/md0
                    mdadm --detail --scan >> /etc/mdadm.conf
                    mkdir /raid
                    mount /dev/md0 /raid
                    put in /etc/fstab
                    Check status:
                        cat /proc/mdstat or mdadm --detail /dev/md0

20. Managing File Systems
        20.1 Diffrences
                XFS: file system developed to deal with large amounts of data
                EXT4: Current file systems
                NFS: The network file system
                SMB/CIFS: File system to interface windows compatible shares
                FAT: The most compatible file system
                NTFS: A windows NTFS implementation
                Brtfs: A new Linux File System

        20.2 Using Systemd to Manage Mounts
                Systemd generates mountswith fstab-generator
                These mounts are written to unit files in /run/systemd/generator
                To bypass fstab, mount unit files can be created manually
                You can create service that mounts automaticaly not only in fstab.

        20.3 Monitor FS 
                tune2fs     # Shows and optimizes Ext file systems
                dumpe2fs    # Dumps Ext file system metadata
                xfs_admin   # is used to monitor XFS properties

        20.4 FS Repair (FS should be unmounted before check)
                fsck        # Ext FS check and repair
                xfs_repair  # XFS FS check and repair

21. Common Administration Taks
        21.1 Logrotate
                Logrotate is started as a cronjob, works with /etc/logrotate.conf and /etc/logrotate.d/

        21.2 Journalctl
                journalctl -f               # Real time logs
                journalctl -p err           # Shows error msg only
                journalctl --since "2020-09-09 00:00:00" --until "2020-10-10 00:00:00" 
                journalctl _SYSTEMD_UNIT=sshd.service -o verbose
                vim /etc/systemd/journald.conf 
                systemctl restart systemd-journald
                journalctl --catalog        # View all journal files in /var/log/journal

        21.3 logger
                logger -p local4 <what to log>           # set priority
                

22. Managing Boot Procedure
        22.1 Boot Procedure
                                      POST(power on self test)
                                        |
                                BOOT DEVICE(operating system)
                                        |
                                      GRUB2
                                        | 
                                      kernel
                                     initramfs
                                        | 
                                     SYSTEMD
                                        | 
                                      SHELL

        22.2 Common Boot Options
                Boot from hard disk: UEFI(unified extensible firmware interface - newer)/EFI(extensible firmware interface - older) or BIOS(basic input/output system) legacy
                Boot from optical media: ISO
                Boot from network: PXE,NFS,HTTP/FTP

                Boot loaders:
                    GRUB2 - Default boot loader to start linux from disk (short: it makes sure that kernel will be loaded)
                    Syslinux - common boot loader to boot from network or ISO
                    LILO AND GRUB - legacy
                Those loaders is installed in the boot sector
                
        22.3 BIOS AND UEFI
                In BIOS booting, a 512 bytes MBR is used on disk(4 partitions)
                UEFI works with firmware on the motherboard that corresponds to parts of the OS. Boot order and other boot related items have moved to the OS. In UEFI systems, a /boot/efi partition with type vfat
                is used to contain all settings required to boot. UEFI normally works with GPT parition tables, which allow for addressing of hard disks bigger than 2TiB.(128 partitions)

        22.4 UEFI
                efibootmgr          # makes managing UEFI boot targets possible
                efibootmgr          # lists current targets
                Active boot entires are marked with a *
                efibootmgr -v       # more details
                efibootmgr -n 0002  # change boot order

        22.5 Managing initramfs
                Main purpose of the initramfs is to provide kernel modules required to mount the root file system
                Also offer additional functionality, allowing a system to boot from non=default storage like LVM, encrypted rootFS or a ntwork based rootFS
                The 'dracut' utility has become the standard too to build an initramfs /etc/dracut.conf
                Without configuration or arguments, it will build an initramfs based on current settings

            
        22.6 Managing grub2 configuration
                Grub2 works with an inputfile which typically is in /etc/default/grub and /etc/grub.d/
                grub2-mkconfig -o outputfile generates outputfile that is actually used while booting
                On BIOS systems, this is /boot/grub2/grub.cfg
                On UEFI systems, this is /boot/efi/EFI/<distro>/grub.cfg
                #example 
                GRUB_CMDLINE_LINUX_DEFAULT="quiet" # While booting information is hidden, if u wanna see whats happening delete quiet

        22.7 (Re)Install new grub2 bootloader
                On BIOS systems, grub2-install /dev/sda
                On EUFI systems, grub2-reinsall grub2-efi shim where the shim file contains cryptographic keys that allow for working with secureboot
                
        22.8 Understanding Isolatable Targets
                A systemd target must be isolatable to allow for booting in that target
                Four common targets are used:
                    emergency.target
                    rescue.target
                    multi-user.target
                    graphical.traget

                Enter the GRUB2 boot menu by pressing 'e', find line which one starts with linux16 and in the lines end, add systemd.unit=nnn.target to boot into a non-default target

        22.9 Setting the Default Target
                systemctl get-default
                systemctl set-default nnn.target
                Setting a new default target creates a symbolic link in /etc/systemd/system/default.target, which points to the desired target in /lib/systemd/system
        
        22.10 Runlevels
                0 - halt 
                1 - Single user mode
                2 - Multiuser, without NFS (Same as 3, if you do not have networking)
                3 - Full multiuser mode
                4 - unused
                5 - X11
                6 - reboot

23. Backups
        23.1 Backup strategies
                # A full backup will make a copy of all files, but on large datasets may be very inefficient 
                # An incremental backup will only backup those files that have changed since the last backup and is much more efficient
                # A differential backup is a backup of all files that have changed since the last full backup, and is more efficient in restore than an incremental backup
                # Alternatively, images can be used to clone complete devices
                # Or snapshots can be used by, for example the LVM volume manager, to freeze the current state of a file system

        23.2 Using dd
                dd if=/dev/sda of=/dev/sdb bs=1M                        # Will clone sda disk to sdb
                dd if=/root/grubfile of=/root/grub_backup bs=1M         # Backup grubfile

        23.3 Check File Integrity 
                checksum            # Is a digit that serves as a sum of correct digits in data, and which can be used to detect errors that have occurred during file storage or transmission
                exmaple:
                        md5sum fileexample > file.md5
                        # modify fileexample and than try again
                        md5sum -c file.md5
                        
24. Managing Server Roles
        24.1 Firewalls
                #List services and ports /etc/services
                iptables (alternative for iptables is nftables(on newer distros))
                    on top of iptables can be:
                        firewalld or ufw

        24.2 firewalld
                Zone - a collection of network cards that is facing a specific direction and to which rules can be assigned
                Interfaces - individual network cards, always assigned to zones
                Services - an XML-based configuration that specifies ports to be opened and modules that should be used
                Forward ports - used to send traffic coming in on a specific port to another port which may be on another machine
                Masquerading - provides Network Address Tranlation (NAT) on a router
                Rich rule - extension to the firewalld syntax to make more complex configuration

                firewall-cmd    #default cli
                firewall-cmd --list-services
                firewall-cmd --get-services
                firewall-cmd --add-service=servicename  --permanent
                firewall-cmd --remove-service=servicename

        24.3 iptables
                iptables -A/-I CHAIN(INPUT,OUTPUT,FORWARD) -i/-o eth0 -s/-d x.x.x.x -p upd/tcp --dport/--sport 22 -j LOG/ACCPET/DROP/REJECT
                
                        
            INPUT-->eth0-->OUTPUT           eth1
                     |                       |
                     |<-------FORWARD------->|
                     |                       |
                     ---------Kernel----------
                
                # Allow incoming ssh connection
                iptables -A INPUT -p tcp --dport 22 -j ACCEPT
                iptables -A OUTPUT -m state --state established,related -j ACCEPT
                
                # Change Policy
                iptables -P OUTPUT ACCEPT
                iptables -P INPUT ACCEPT

                iptables-save > /etc/sysconfig/iptables     # to make permanent rules
                
        
        24.4 Dynamic Firewall Rules
                DenyHosts: monitors and blocks unpremitted access to SSH servers
                Fail2Ban: a more inclusive service that allows for blocking of unwated trafic, works for SSH bt also for web servers
                IPset: an extension to iptables which makes it possible to work with a more intuitive syntax, and more advanced options

                DenyHosts:
                    yum install python-ipaddr epel-release denyhost fail2ban 
                    systemctl enable fail2ban
                    fail2ban-client status


25. Managing Linux Server Roles
        25.1 SSH 
                ssh-keygen                  # Generate key pairs
                ssh-copy-id user@IP         # Copy pub key to remote server

                ssh-agent /bin/bash         #cache passphrase
                ssh-add enter 'passphrase'

        25.2 TIME
                timedatectl, ntpd or chronyd used to synchronize time
        
        25.3 Managing Certificate Services
                PKI stands for Public Key Infrastructure
                It is the infrastructure that provides public/private keys that can be used to secure services
                Typically, signing happens by using an external Cerficiate Authority (CA)

        25.4 Mail Services
                SMTP is the mail sending protocol, it is typically implemented by the Postfix mail server or sendmail
                POP3 and IMAP are typically used for receiving mail, the most common service that implements these is Dovecot

                # Simple Example with Postfix to receive email
                vim /etc/postfix/main.cf                                                # Main config file
                mydomain = YourDomain.ltd
                inet_interfaces = all                                                   # To receive email from external devices
                inet_protocols = ipv4
                mydestination = $myhostname, localhost.$mydomain, localhost, $mydomain  # Gets emails
                systemctl restart postfix
                ufw allow smtp

        25.5 NFS(Network File System) File service 
                # Implemented at a Linux Kernel level
                # Shares are defined in /etc/exports
                # nfs-server service offers access to these shares
                # TCP 2049
                # showmount -e servername to discover shares
                # mount -t nfs server:/share /mountpoint
                # Configuration Example:
                yum install nfs-utils 
                mkdir /sharefolder
                vim /etc/exports
                    /share  *(rw,no_root_squash)    * - all servers, no_root_squash - root allowed
                enable nfs-server
                ufw allow nfs
                mount [-t] server:/share /mnt

        25.6 FTP
                sftp : part of the ssh suite
                vsftp : very secure
                tftp : works without authentication
                # example to configure vsftp
                    yum install vsftp
                    vim /etc/vsftpd/vsftpd.conf
                    enable service
                    on client side install ftp client(lftp)
                    lftp servername or IP
        
        25.7 Authentication Services
                PAM - can be used to instruct login related binaries to connect to an external authentication server
                FreeIPA - is a common Linux based authetication server
                Alternatives are OpenLDAP or Active Directory

        25.8 PROXY
                Proxy services can be used to regulate access to websites on the INTERNET
                Squid is the most commonly used Linux-based Proxy Server
                A reversed proxy can be used to regulate access to services that are exposed on your local network (Load Balancing)
                Nginx is offering a commonly used reversed proxy

        25.9 Load Balancing
                A load baclancer can be used in front of those services and distribute the work load over all the instances
                HAProxy is the most common Linux load balancer

        25.10 Managing Clustering
                HA cluster can be used to unsure that if a critical service goes down it normaly automatically started again
                HA clustering on Linux can be implemented by the Pacemaker Service
                In a Pacemaker cluster, 2 or more nodes are configured to guarantee the availability of services
                The Corosync layer of the Pacemaker cluster watches node availability 
                The crmd(cluster resource management daemon) process watches the availability of monitored processes
                To guarantee that failing nodes are properly terminated, STONITH(shoot the another node into head) is used
                

26. Advanced Administration Tasks
        26.1 Managing Boot loader Password
                GRUB2 can be protected with password to make canges and for a password that is required for booting anything
                grub2-setpassword   # On RHEL and related, to set password for modifications
                This will creates a file /boot/grub2/user.cfg containing user name and password
                After a reboot, to make changes the user will be prompted for a password

        26.2 Securing SSH
                PermitRootLogin no              # Disable root login
                AllowUser User                  # Allow specific user login
                PasswordAuthenitication no      # Disable password authentication
                Port 2020                       # Chane SSH service port

        26.3 Managing chroot Jails
                A chroot jail is an isolated env where users and processes dont get acccess to onther part of the OS
                Chroot jails are typically used by specific processes and need to be setup(and supported) by these processes
                In a chroot jail, the user need to have access to all revelant files and processes
                This includes a shell, binaries like 'ls' and etc. but also the libraries used by these binaries
                #apt/yum search chroot
        
        26.4 Paritioning for Security
                While creating partitions its good idia to seprate different file systems to enhance security
                # Make sure OS data is separated from application data
                # Put log files on a seprate partition to prevent your system from filling up completely
                When creating partitions, mount options can be used to limit security risks:
                ro: read-only       # rare
                noexec: users cannot run executable files
                nosuid: denies any applications that run with SUID permissions

        26.5 Using OpenSCAP and Security Profiles
                OpenSCAP makes it possible to check a systems compliancy to security settings that are defined in a policy
                Defferent standard policies exist, such as the Commercial Cloud Services (C2S) baseline that was created by USA gov.
                The scanner is the component that reads the policy and evaluates to see if a system is compliant
                # yum install scap-workbench openscap scap-security-guide

        26.6 Auditing
                systemctl status auditd
                /var/log/audit/audit.log
                auditctl -w /etc/shadow -p wa # add event
                auditctl -w /etc/ -p wa       # add event /etc dir
                ausearch -i | grep shadow

        26.7 Configure MOTD
                For security compliancy, usage policies should be posted in /etc/motd
                Doing so is easy, just write a message in this file and the file contents is shown every time a user logs in 
                Alternatively there is /etc/issue which is used to display a message before a user is logging in

        26.8 Disable ctrl-alt-delete
                systemctl mask ctrl-alt-del.target to disable
                systemctl daemon-reload

        26.9 LUKS Disk encryption
                # Create Partition
                 'cryptsetup luksFormat /dev/sdb1' - will format the LUKS device
                 'cryptsetup luksOpen /dev/sdb1 NAME'- will open it and create a device mapper name
                # create filesystem on device
                # mount the resulting device mapper device
                # To automate the cryptsetup luksOpen use /etc/crypttab
                # Automate mounting add to /etc/fstab
                'cryptsetup luksClose /dev/mapper/NAME'


27. User Interfaces
        27.1 Display Servers (for noobs only)
                X11 has been the display server for a long time
                On mordern linux distros X11 is being replaced with Wayland
                loginctl                                # Shows current sessions, notice the session ID
                loginctl show-session <ID> -p Type      # Show the session type

        27.2 Graphical server installation and configuration
                /etc/X11                # Configuration of X11 happens through defferent files in here
                /etc/gdm/custom.conf    # GDM display manager can use the configuration file to specify which graphical sever should be used

        27.3 Graphical Desktops
                Gnome (default on RED)
                KDE
                MATE (based on gnome2)
                Unity (default on ubuntu based on gnome3)
                Cinnamon (mint)

        27.4 RDP
                VNC
                XRDP
                NX
                Spice

        27.5 Configure console redirections
                ssh -X                              # Is used to enable X11 Forwarding in a way that is subjected to X11 security extension restrictions
                ssh -Y                              # enables trusted X11 Forwarding which is not subject to X11 security extension restictions
                /etc/ssh/ssh_config ForwardX11 yes  # To configure trested X11 forwarding and give clients full access to the X11 display


28. Managing Virtualization

        28.1 Types of virtualization
                    Type2                  Type1(most common )

               | OS OS OS OS|          | OS OS OS  |
               | VIRTUAL BOX|          | Hypervisor|
               |     OS     |          |     HW    |
               |     HW     |
                
            # Xen,KVM,Vmware,HyperV
        
        28.2 Understand Containers
                                                
                |    App|App|App    |
                |  Container engine |
                |      OS           |
                |      HW           |

            # LXC, systemd-nspawn, docker(common), RKT(newest)
        
        28.3 IAAS(Infrastructure as a service) cloud  
                # AWS,Azure,Google cloud
                
        28.4 KVM Virtualization
                KVM is a part of the Linux kernel and is available when the 'kvm' and 'kvm_platform' modules are loaded
                To Run KVM vms, CPU support for virtualization must be available
                Tools are provided by the Qemu project
                A management interface is provided by 'libvirtd', which is typically started as a service by systemd
                'virsh' is the common CLI managment tool, 'virt-manager' provides a graphical interface for managining vms
                grep vmx /proc/cpuinfo      # Check flags if cpu supports virtualization
                lsmod |grep kvm             # Check if modules loaded
                systemctl status libvirtd   
                yum install virt-manager
                yum provides *virsh
                yum install libvirt-client  # Install virsh command

        28.5 Containers
                Containers are the easy way to run application workloads in a strictly protected env
                Containers are started from images, which are available through private reigstries, or public registries such as the Docker registry

                yum install docker
                enable
                docker search fedora
                docker pull fedora
                docker run fedora /bin/bash or docker run -it fedora /bin/bash (-it - interactive terminal)
                ctrl-p, ctrl-q      # Gets out from container without closing it. if exit it will close countainer
                docker ps
                
        28.6 Virtualization Storage
                Thin provisioning makes sense in that case: the upper limit is defined, but not claimed immediately
                Thic provisioning makes sense in that case: a VM need to offer the best possible storage performance
                Persistent volumes can be allocated as storage external to the VM, where the storage will survive the VM

                Defferent backends can be usded for VM block devices:
                    Direct connection to a block device (not common)
                    Qcow, VMDK (most common,cloud env, vmware, kvm)
                    Blob storage    (Microsoft Azure env)

        28.7 Virtualization Networking
                brctl show

        28.8 Common Templates And Formats in Virtualization
                OVF: Open Virtualization Format is an open standard for packaging virtual appliances that is supported by  most virtualization solutions
                The contents consists of a directory tree and an XML file that is used to describe the contents

                OVA: Open Virtualization Archive is a common archiving format to package OVF files.

                A markup language: provides a language format that is used for easy creation of objects that can be created in an IT env.
                YAML: which stands for YAML aint Markup Language is an easy to use file format where indentation is used to identify relations between the different objects specified in the file
                (ansible)
                JSON (JavaScript Object Notation) is another format, where items are grouped using curly brackets
                XML


29 Managining Secure Access Control
        29.1 PAM (Plugable authentication modules)
                ldd /usr/bin/login | grep pam          # List binaries
                ll /etc/pam.d/
                
        29.2 Configure PAM
                /etc/securetty
                remove tty3
                chvt 3          # cant login with root  
                vim /etc/pam.d/login
                auth     required       pam_tally2.so deny=2 lock_time=60   # After 2 incorect logins, locks user for 60s

        29.3 Managing TCP Wrappers
                Provide an older solution to specify allowed and denied actions
                /etc/hosts.deny and /etc/hosts.allow are usded to describe what is allowed
                    Recommended to set to ALL:ALL to deny all access that hasnt been specifically allowed

        29.4 VPN
                OpenVPN common
                Using TLS/SSL, default port 1194
                yum install opel-release and openvpn easy-rsa
                /usr/share/doc/openvpn-x.x.x/samples       # Sample files
                /etc/openvpn/server.conf


30. SELinux and AppArmor
        30.1 Mandatory Access Control(MAC)
                Default Linux Access Control is discretionary - every user can grant permissions to other users
                Also, standard Linux security is a collection of tools that focus on specific areas of the OS
                That leaves Linux vulnerable for specific types of problems, like zero day exploits
                Thats why Mandatory Access Control (MAC) is needed
                There are two solutions for MAC: SELinux and AppArmor

        30.2 SELinux vs AppArmor
                SELinux locks down everything: if it isnt allowed, it is denied
                AppArmor works with profiles to secure specific services
                AppArmor is relatively easy to learn
                SELinux is more comples
                SELinux offers more advanced features, such as multi-level security
                SELinux uses filesystem labels and ports

        30.3 AppArmor
                /etc/apparmor.d/            # Profiles available here
                aa-genprof /you/aplication  # Create new profile
                Run the application from another terminal
                press 's' to scan for application events
                Loaded profiles are in      /sys/kernel/security/apparmor
                Alternative                 aa-status
                TIP: AppArmor CLI tools start with 'aa-'
                aa-genprof vim              # To generate profile
                
        30.4 AppArmor Troubleshooting
                Ensure that apparmor-utils is installed
                apparmor_status             # Gives a generic overview of that is currently working
                aa-complain                 # Set modules in complain mode, to lrean what they are doing
                aa-enforce                  # After verifying that a module is working, set to enforce mode
                aa-logprof                  # To see messages that were generated and are not currently covered by a profile
                aa-notify                   # To show desktop messages when AppArmor blocks something
                
        30.5 SELinux modes
                Integrated into Linux Kernel
                setenforce 0                # Switch to Permissive mode, logs /var/log/audit/audit.log
                setenforce 1                # Switch to Enforcing mode
                getenforce                  # Check for current SELinux mode

                        Enforcing(Full operate,logs block)  Permissive(logging only, but dont block)
                                |                               |
                                |                               |
                                |                               |
                                ---------------Enabled-----------
                                                  |
                                                  |
                                                  |
                                                Kernel
                                            /etc/sysconfig/selinux
                                                  |
                                                  |
                                                  |
                                               Disabled
        
        30.6 Working with SELinux lables
                All items are using context lables
                The context type is whats most important about them
                semanage fcontext           # To set context labels on files, this will write to the policy
                After setting context labels on files, use 'restorecon' to apply from policy to the inodes
                semanage port               # Set context labels on network ports
                ls -Z                       # Find labels on files u can use -Z on processes 'ps' 
                # Example, we want change WebRootDir to /web
                ls -Z /var/www
                lz -Zd /web
                semanage fcontext -a -t httpd_sys_content_t "/web(/.*)?" 
                restorecon -Rv /web

        30.7 Managing SELinux Booleans
                A boolean is an on/off switch that allow you to easily apply settings in SELinux
                Booleans are used in addition to context labels
                getsebool -a            # To get a list of all
                setsebool -P            # To make persistent changes to booleans, without -P it will disapear after reboot
                setsebool -P ftpd_anon_write on     # enable anonymous to write

        30.8 TroubleShooting SELinux
                /var/log/audit/audit.log
                Not always readable, use sealert
                grep sealert /var/log/messages


31. TroubleShooting Linux Issues
        31.1 NETWORK
                nmap            # Analyze open ports
                netstat / ss    # List Local ports
                iftop           # live overview of netowkr traffic on all local interfaces
                route           # useed to manipulate the routing table
                iperf           # is installed on server and client to measure network throughput
                tcpdump
                wireshark
                ipset           # extension to iptables and allows administrators to set firewall rules
                netcat          # is the Swiss Army Knife for networking and contains many tools
                traceroute      # Analyze PAth
                tracepath       # Similar as traceroute
                mrt             # Combined traceroute and ping commands
                arp             # Shows IP address to MAC address resolution tables
                nslookup/dig
                whois
                ping
                ip              # Check Run time network configuration
                
                #EXAMPLES
                nmap -sn 192.168.0.0/24         # Scans network 
                ss -tunap                       # Shows open ports
                
        31.2 STORAGE
                fsck        # Is used to monitor file system integrity
                iostat      # Can generate a wide range of storage related statistics
                ioping      # Is used to test I/O performance
                To optimize I/O performance, the I/O scheduler can be tuned through the /sys filesystem
                #EXAMPLES
                iostat 2 5  # 2 sec interval, 5 times
                output: Device, tps (transactions per second)
                ioping /dev/vda1
                #OPTIMIZATION
                vim /sys/block/sda/queue/scheduler

        31.3 CPU
                /proc/cpuinfo       # Detail cpu info
                sar 
                sysctl              # Tuning
               
        31.4 MEMORY
                A Healthy system should have at least 20% of RAM available as free or cached memory
                /proc/meminfo
                iostat
                vmstat 2 5          # si/so -swap in/swap out, bi/bo -block in/block out         if si/so is close to bi/bo ITS BAD, bi/bo should be always bigger than si/so
                check logs for out of memory killer (OOM)

        31.5 RESET ROOT PASSWORd
                rw init=/bin/bash or rd.break 
                rd.break is more powefull

                Load grub, in the end of the line which loads kernel add 'rd.break' or 'init=/bin/bash'
                hit CTRL+x
                mount -o remount,rw /sysroot
                chroot /sysroot
                passwd
                ON CENTOS only (if SELinux enabled): touch /.autorelabel
                # if cant do any commands do:   
                    exec /sbin/init


32. GIT (version control system)
        32.1 GIT
                Git repository consists of three ress maintained by GIT
                The working directory holds actual files
                The Index acts as a staging area
                The HEAD points to the last commit that was made
                When working with Git, the 'git add' command is used to add files to the index
                To commit these files, use 'git commit -m "commit message"' 
                Use 'git add origin https://server/reponame' to connect to the remote repository
                To complete the sequence, use 'git push origin master'. Replace 'master' with the actual branch you want to push changes to
            
                # Create the repository on you Git server
                # Set you user information
                    git config --global user.name "You NAme"
                    git config --global user.email "EMAIl@Email.com"
                # Create a local directory that contains a README.md file with some contents
                    git init                            # T o generate the Git repository metadata
                    git add <filename>                  # To add files to the staging area
                # from there use 'git commit -m "commit mesg"' to commit the files. This will commit the files to HEAD, but not to the remote repository yet.
                    git remote add origin https://server/reponame
                    git push -u origin master           # To push files to remote repository
            
                #EXAMPLE. Go to github.com, create user, than create repository for example TESTAS
                ON client (server), mkdir TESTAS, put files scripts what ever u want. 
                git config --global user.name "name"
                git config --global user.email "email"
                # After this will be created dir .gitconfig
                cd /Testas
                vim README.md
                git init
                git add *file-names
                git commit -m "initial upload" (commited to HEAD )
                git remote add origin https://github.com/USER/TESTAS
                git push -u origin master
                promt user/password

        32.2 Using GIT
                git clone https://gitserver/reponame    # To clone the contents of remote repository to your computer
                git pull                                # To update the local repository to the latest commit
                git diff <branch1> <branch2>            # To proview branch differences and see if there are any potential conflicts
                git merge <brucnh>                      # To merge another branch in your active branch
            
                Modified files need to go through the staging process
                git status                              # After changing files, use this command to see which files have changed
                git add                                 # To add these files to the staging area
                git rm <filename>                       # To remove files
                #After that u can commit changes
                git push origin master                  # To synchronize changes
                git pull                                # From client, to update your current Git clone

        32.3 Git Branches
                Branches are used to develop new features in isolation from the main brach
                The master branch is the default brach, others braches can be manually added
                After completion, merge the branches back to the master

                git checkout -b dev-brach               # To create a new branch and start using it
                git push origin dev-brach               # to push the new branch to the remote repo
                git checkout master                     # Switch back to the master branch
                git brach -d dev-brach                  # To delete branch


33. BASH POWERRRR BASIC :)
        33.1 Shell script components
                #!/bin/bash\|perl\|python
                echo PrintWhatEverYouWant
                read InputWhatEverYouWant
                cat $DoWhatEverYouWant

        33.2 Loops 
                if .. then .. fi
                while .. do .. done
                until .. do .. done
                case .. in .. esac
                for .. in .. do .. done
    
                # Example
                "man test"
                echo $? - exit code in the last command
                if [ -z $1 ]
                then
                echo "you dont have args"
                exit 20
                fi
                echo "arg is $1"
        
        33.3 Adv ALMOST :D
                counter=$1
                counter=$(( counter * 60 ))           

                function(){
                        counter=$(( counter - 1 ))
                        sleep 1
                }
                
                while [ counter -gt 0 ]
                do
                echo you still have $counter seconds left
                function
                done

                [ $counter = 0 ] && echo time is up $$ function
                [ $counter = "-1" ] && echo you are one second late && function

                while true
                do
                echo you now are ${counter#-} seconds late                          # #- removes - from the begning
                function
                done

                


