param(
	[ValidateNotNullOrEmpty()]
	[ValidateSet('Default', 'StartInternalTask-1', 'StartInternalTask-2', 'StartInternalTask-3', 'CheckInternalTask')]
	[string] $mode = "Default"
)

$ErrorActionPreference = "Stop"

#region Configuration

$subscriptionId="xxxxxxxx-xxxxx-xxxx-xxxx-xxxxxxxxxxxx"

# source VM (generation V1)
$sourceVmName          = "T-WVD-Basic-20"
$sourceVmResourceGroup = "WVD_TEMPLATES"

# target VM to be build (generation V2) - This wil be a copy of the source VM but as V2 generation
$targetVmName          = "T-WVD-Basic-30" # max. length is 15
$targetVmResourceGroup = "WVD_TEMPLATES"

$enabledTrustedLaunch = $true

$usePremium = $false   # if $true, this speeds up the process but can only be done, if the VM size suppports premium disks
$tempDiskSizeGb = 512  # must be larger to store the wim file of the original disk of the source

#endregion


#region InternalMethods

$scriptPath  = $PSCommandPath
if (-not $PSCommandPath) {$scriptPath="C:\1Drive\OneDrive - sepago GmbH\Desktop\Convert-VmV1toV2.ps1"}
$localPath   = Split-Path $scriptPath -Resolve
$logFileName = "$(Split-Path $scriptPath -Leaf).log"


function LogWriter($message) {
	$message = "$(Get-Date ([datetime]::UtcNow) -Format "o") $message"
	write-host($message)
	if ([System.IO.Directory]::Exists($env:temp)) { try { write-output($message) | Out-File "$localPath\$logFileName" -Append } catch {} }
}

#endregion InternalMethods


#region MainApp

    LogWriter ("Starting in mode: $mode")

    #region CreateTheAzureResources

    if ($mode -eq "Default") {
        if(!(Get-AzContext)) {
            # Connect to Azure if no connection exists
            Connect-AzAccount
        }
        
        # select subscription
        Get-AzSubscription -SubscriptionId $subscriptionId | Select-AzSubscription

        # check, if some of the new resources exist
        if (Get-AzDisk -ResourceGroupName $targetVmResourceGroup -DiskName "$($sourceVmName)-Disk-Copy" -ErrorAction SilentlyContinue) {LogWriter "The target disk $sourceVmName exist. Please delete it first."; break}
        if (Get-AzDisk -ResourceGroupName $targetVmResourceGroup -DiskName "$($targetVmName)-Disk-Converted" -ErrorAction SilentlyContinue) {LogWriter "The converted disk $($targetVmName)-Disk-Converted exist. Please delete it first."; break}
        if (Get-AzSnapshot -ResourceGroupName $targetVmResourceGroup -SnapshotName "$($sourceVmName)-Disk-Snap" -ErrorAction SilentlyContinue) {LogWriter "The snapshot $($sourceVmName)-Disk-Snap exist. Please delete it first."; break}
        if (Get-AzVm -ResourceGroupName $targetVmResourceGroup -Name $targetVmName -ErrorAction SilentlyContinue) {LogWriter "The target VM $targetVmName exist. Please delete it first."; break}


        # read data of the existing VM
        LogWriter ("Getting data of the source VM")
        $sourceVm=Get-AzVm -ResourceGroupName $sourceVmResourceGroup -Name $sourceVmName
        $sourceNic=Get-AzNetworkInterface -ResourceId $sourceVm.NetworkProfile.NetworkInterfaces[0].Id
        $location=$sourceNic.Location
        $subnetId=$sourceNic.IpConfigurations[0].Subnet.Id

        $sourceDisk = Get-AzDisk -ResourceGroupName $sourceVm.StorageProfile.OsDisk.ManagedDisk.Id.Split("/")[4] -DiskName $sourceVm.StorageProfile.OsDisk.ManagedDisk.Id.Split("/")[8]
        if ($sourceDisk.HyperVGeneration -like "V2") {
            Write-Host "Source VM is still a V2 VM"
            exit
        }

        # create target VM with a temporary Windows 11 to do the migration
        LogWriter ("Creating the target VM (V2)")
        $psc = New-Object System.Management.Automation.PSCredential("vmAdmin", (ConvertTo-SecureString "Sup+rTempS+cret123---" -AsPlainText -Force))
        $nic = New-AzNetworkInterface -Name "nic-$($targetVmName)" -ResourceGroupName $targetVmResourceGroup -Location $location -SubnetId $subnetId -Force

        $vmConfig = New-AzVMConfig -VMName $targetVmName -VMSize $sourceVm.HardwareProfile.VmSize
        $vmConfig = Set-AzVMBootDiagnostic -VM $vmConfig -Enable
        $vmConfig = Set-AzVMSourceImage -VM $vmConfig -PublisherName "MicrosoftWindowsServer" -Offer "WindowsServer" -Skus "2022-Datacenter-g2" -Version "latest"  # must be a V2 image
        $vmConfig = Set-AzVMOSDisk -VM $vmConfig -DiskSizeInGB $tempDiskSizeGb -CreateOption FromImage
        $vmConfig = Set-AzVMOperatingSystem -VM $vmConfig -ComputerName $targetVmName -Windows -EnableAutoUpdate -Credential $psc
        $vmConfig = Add-AzVMNetworkInterface -VM $vmConfig -Id $nic.Id
        if ($enabledTrustedLaunch) {
            $vmConfig = Set-AzVMSecurityProfile -VM $vmConfig -SecurityType "TrustedLaunch"
            $vmConfig = Set-AzVmUefi -VM $vmConfig -EnableVtpm $true -EnableSecureBoot $true
        }
        
	if ($sourceVm.LicenseType -eq $null) {
            New-AzVM -VM $vmConfig -ResourceGroupName $targetVmResourceGroup -Location $location
        } else {
            New-AzVM -VM $vmConfig -ResourceGroupName $targetVmResourceGroup -Location $location -LicenseType $sourceVm.LicenseType
        }
	
        $targetVm = Get-AzVM -ResourceGroupName $targetVmResourceGroup -Name $targetVmName
        $targetDiskOrg = Get-AzDisk -ResourceGroupName $targetVmResourceGroup -DiskName $targetVm.StorageProfile.OsDisk.Name

        # copy the source disk with a snapshot
        LogWriter ("Creating a copy of the source VM")
        $snapShotConfig = New-AzSnapshotConfig -SourceUri $sourceVm.StorageProfile.OsDisk.ManagedDisk.Id -Location $location -CreateOption copy
        $sourceDiskSnap = New-AzSnapshot -ResourceGroupName $targetVmResourceGroup -SnapshotName "$($sourceVmName)-Disk-Snap" -Snapshot $snapShotConfig # clean-up after use
        $diskConfig = New-AzDiskConfig -Location $location -SourceResourceId $sourceDiskSnap.Id -CreateOption Copy -SkuName $sourceDisk.Sku.Name
        if ($usePremium) {$diskConfig.Sku=[Microsoft.Azure.Management.Compute.Models.DiskSku]::new('Premium_LRS')}
        $sourceDiskCopy = New-AzDisk -Disk $diskConfig -ResourceGroupName $targetVmResourceGroup -DiskName "$($sourceVmName)-Disk-Copy"

        # create the new target disk to hold the data of the source disk (but as a V2 type)
        LogWriter ("Create an empty V2 disk as destion for the data")
        $diskConfig = New-AzDiskConfig -Location $location -SkuName $sourceDisk.Sku.Name -OsType Windows -HyperVGeneration V2 -DiskSizeGB $sourceDisk.DiskSizeGB -CreateOption "Empty" 
        if ($enabledTrustedLaunch) {$diskConfig = Set-AzDiskSecurityProfile -Disk $diskConfig -SecurityType "TrustedLaunch"}
        if ($usePremium) {$diskConfig.Sku=[Microsoft.Azure.Management.Compute.Models.DiskSku]::new('Premium_LRS')}
        $targetDisk = New-AzDisk -Disk $diskConfig -ResourceGroupName $targetVmResourceGroup -DiskName "$($targetVmName)-Disk-Converted"

        # attach the copy of the source disk (V1)
        LogWriter ("Attaching the copied source disk to the target VM: Lun 6")
        $targetVm = Add-AzVMDataDisk -VM $targetVm -Name $sourceDiskCopy.Name -CreateOption Attach -ManagedDiskId $sourceDiskCopy.Id -Lun 6 -Caching ReadWrite
        Update-AzVM -VM $targetVm -ResourceGroupName $targetVmResourceGroup

        # attach the later target disk (V2)
        LogWriter ("Attaching the empty target disk to the target VM: Lun 7")
        $targetVm = Add-AzVMDataDisk -VM $targetVm -Name $targetDisk.Name -CreateOption Attach -ManagedDiskId $targetDisk.Id -Lun 7 -Caching ReadWrite
        Update-AzVM -VM $targetVm -ResourceGroupName $targetVmResourceGroup

        # target VM is ready with all attached disks
        # now we have to work with the partitions inside of the VM - Invoking this script with the parameter -mode StartInternalTask-1
        LogWriter ("Run the first part of the converting process on the target VM - this can last hours")
        Invoke-AzVMRunCommand -ResourceGroupName $targetVmResourceGroup -Name $targetVmName -CommandId "RunPowerShellScript" -ScriptPath $scriptPath -Parameter @{"-mode" = "StartInternalTask-1"}
        
        # While the script is running internally, we have to wait for completion - looping every 2 minutes (the task can take seeral hours)
        $completed = $false
        $failed    = $false
        do {
            Start-Sleep -Seconds 120
            try {
                $rv = Invoke-AzVMRunCommand -ResourceGroupName $targetVmResourceGroup -Name $targetVmName -CommandId "RunPowerShellScript" -ScriptPath $scriptPath -Parameter @{"-mode" = "CheckInternalTask"}
            } catch {
                LogWriter ("The remote operation failed: $_")
                $failed = $true
                $completed = $true
            }
            LogWriter ("Waiting for the remote task - long running operation")
            if ($rv.Value[0].Message.Contains("###:COMPLETE:###")) {
                $completed = $true
                LogWriter ("The remote opertion completed")
            }
            
        } while (-not $completed)

        # 2nd step inside the VM: use dism to write the image to the new disk
        if (-not $failed) {
            # now we have to work with the partitions inside of the VM - Invoking this script with the parameter -mode StartInternalTask-1
            LogWriter ("Run the second part of the converting process on the target VM - this can last hours")

            Invoke-AzVMRunCommand -ResourceGroupName $targetVmResourceGroup -Name $targetVmName -CommandId "RunPowerShellScript" -ScriptPath $scriptPath -Parameter @{"-mode" = "StartInternalTask-2"}
        
            # While the script is running internally, we have to wait for completion - looping every 2 minutes (the task can take seeral hours)
            $completed = $false
            $failed    = $false
            do {
                Start-Sleep -Seconds 120
                try {
                    $rv = Invoke-AzVMRunCommand -ResourceGroupName $targetVmResourceGroup -Name $targetVmName -CommandId "RunPowerShellScript" -ScriptPath $scriptPath -Parameter @{"-mode" = "CheckInternalTask"}
                } catch {
                    LogWriter ("The remote operation failed: $_")
                    $failed = $true
                    $completed = $true
                }
                LogWriter ("Waiting for the remote task - long running operation")
                if ($rv.Value[0].Message.Contains("###:COMPLETE:###")) {
                    $completed = $true
                    LogWriter ("The remote opertion completed")
                }
            
            } while (-not $completed)        
        
        }
        # last step inside the VM: create UEFI partition
        if (-not $failed) {
            LogWriter ("Run the last part of the converting process on the target VM")
            Invoke-AzVMRunCommand -ResourceGroupName $targetVmResourceGroup -Name $targetVmName -CommandId "RunPowerShellScript" -ScriptPath $scriptPath -Parameter @{"-mode" = "StartInternalTask-3"}
        }

        if (-not $failed) {
            # ready with the internal work
            # stop the target VM
            LogWriter ("Deallocate the target VM")
            Stop-AzVM -ResourceGroupName $targetVmResourceGroup -Name $targetVmName -Force

            # detach the copy of the source disk (V1)
            LogWriter ("Detach the copied source disk")
            $targetVm = Remove-AzVMDataDisk -VM $targetVm -Name $sourceDiskCopy.Name
            Update-AzVM -VM $targetVm -ResourceGroupName $targetVmResourceGroup

            # detach the later target disk (V2)
            LogWriter ("Detacht the target disk")
            $targetVm = Remove-AzVMDataDisk -VM $targetVm -Name $targetDisk.Name
            Update-AzVM -VM $targetVm -ResourceGroupName $targetVmResourceGroup

            # swap os-disk
            LogWriter ("Swap OS disk to have the converted disk as the OS disk")
            $targetVm = Get-AzVM -ResourceGroupName $targetVmResourceGroup -Name $targetVmName
            $targetVm = Set-AzVMOSDisk -VM $targetVm -ManagedDiskId $targetDisk.Id -Name $targetDisk.Name
            Update-AzVM -VM $targetVm -ResourceGroupName $targetVmResourceGroup
            LogWriter ("Starting the converted target VM")
            Start-AzVM -ResourceGroupName $targetVmResourceGroup -Name $targetVmName

            # clean-up
            LogWriter ("Cleaning up")
            $sourceDiskSnap | Remove-AzSnapshot -Force
            $sourceDiskCopy | Remove-AzDisk -Force
            $targetDiskOrg | Remove-AzDisk -Force
            LogWriter ("We are ready. The new V2 VM $targetVmName is ready and a copy of the original VM (which could be removed if everything works as expected")

        } else {
            # something went wrong - stopping the process to let the admin doing some debugging
            LogWriter ("Error: Something went wrong - stopping the process to let the admin doing some debugging. Remember to clean-up manually (disks, snapshots, VM)")
        }
    }

    #endregion CreateTheAzureResources

    #region RunOnTheNewVmAndHandleDisks
    
    if ($mode -eq "StartInternalTask-1") {
        LogWriter ("Preparing the disks and partitions")
        $targetDiskNumber = (Get-Disk | Where-Object {$_.Path -like "*&000007#*"}).Number # lun=7
        $sourceDiskNumber = (Get-Disk | Where-Object {$_.Path -like "*&000006#*"}).Number # lun=6

        $diskPath=(Get-Disk -Number $targetDiskNumber).Path


        Get-Disk -Number $targetDiskNumber | Initialize-Disk -PartitionStyle GPT -ErrorAction SilentlyContinue

        # exclude defender
        LogWriter ("Set defender excludes to speed up the imaging and apply process")
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions" -Name "Paths" -Force -ErrorAction Ignore
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths" -Name "1" -Value "S:\" -force -ErrorAction Ignore
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Exclusions\Paths" -Name "2" -Value "T:\" -force -ErrorAction Ignore
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions" -Name "Paths" -Force -ErrorAction Ignore
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" -Name "S:\" -Value 0 -force -ErrorAction Ignore
        New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths" -Name "T:\" -Value 0 -force -ErrorAction Ignore

        # delete all partion if needed
        Remove-Partition -DiskNumber $targetDiskNumber -PartitionNumber 2,3,4,5,6,7,8,9 -Confirm:$false -ErrorAction SilentlyContinue


        # Create UEFI partition
        LogWriter ("Create UEFI partition")
        $uefi=New-Partition -DiskNumber $targetDiskNumber -Size 100MB -GptType "{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}" -IsHidden
        Format-Volume -FileSystem FAT32 -NewFileSystemLabel "SYSTEM" -Path $uefi.DiskPath

        # Create recovery partition
        LogWriter ("Create recovery partition")
        $recovery=New-Partition -DiskNumber $targetDiskNumber -Size 450MB -GptType "{de94bba4-06d1-4d40-a16a-bfd50179d6ac}" -IsHidden


$null = @"
select disk $targetDiskNumber
select partition $($recovery.PartitionNumber)
gpt attributes=0x8000000000000001
exit
"@ | diskpart.exe


        # Create windows partition
        LogWriter ("Create Windows partition")
        $windows=New-Partition -DiskNumber $targetDiskNumber -UseMaximumSize

        # mount partitions
        LogWriter ("Mount partitions")
        Remove-PartitionAccessPath -DiskNumber $sourceDiskNumber -PartitionNumber 2 -AccessPath (Get-Partition  -DiskNumber $sourceDiskNumber -PartitionNumber 2).AccessPaths[0] -ErrorAction SilentlyContinue
        Add-PartitionAccessPath -DiskNumber $sourceDiskNumber -PartitionNumber 2 -AccessPath "S:\"
        Add-PartitionAccessPath -DiskNumber $targetDiskNumber -PartitionNumber $uefi.PartitionNumber -AccessPath "U:\"
        Add-PartitionAccessPath -DiskNumber $targetDiskNumber -PartitionNumber $recovery.PartitionNumber -AccessPath "R:\"
        Add-PartitionAccessPath -DiskNumber $targetDiskNumber -PartitionNumber $windows.PartitionNumber -AccessPath "T:\"

        # Format drives
        LogWriter ("Format partitions")
        Format-Volume -FileSystem NTFS -NewFileSystemLabel "Windows Sytem Drive" -DriveLetter T:\ -ErrorAction SilentlyContinue
        Format-Volume -FileSystem NTFS -NewFileSystemLabel "SYSTEM" -DriveLetter R:\ -ErrorAction SilentlyContinue
        Format-Volume -FileSystem FAT32 -NewFileSystemLabel "SYSTEM" -DriveLetter U:\ -ErrorAction SilentlyContinue


        # Capture the source windows
        # Dism /Capture-Image /ImageFile:`"C:\Capture.wim`" /CaptureDir:S:\ /Name:Captured
        # Start dism but don't wait
        LogWriter ("Starting DISM to create an image")
        Start-Process -FilePath Dism.exe -ArgumentList "/Capture-Image /ImageFile:`"C:\Capture.wim`" /CaptureDir:S:\ /Name:Captured"
        Start-Sleep -Seconds 30
    }

    if ($mode -eq "StartInternalTask-2") {
        # Rollout the image to the target disk
        # Dism /Apply-Image /ImageFile:"C:\Capture.wim" /ApplyDir:T:\ /Index:1 /CheckIntegrity
        LogWriter ("Starting DISM and apply image to the new Windows partition on the V2 disk")
        Start-Process -FilePath Dism.exe -ArgumentList "/Apply-Image /ImageFile:`"C:\Capture.wim`"  /ApplyDir:T:\ /Index:1 /CheckIntegrity"
        Start-Sleep -Seconds 30
    }

    if ($mode -eq "StartInternalTask-3") {
        # Create UEFI
        LogWriter ("Writing UEFI data to UEFI partition")
        Start-Process -Wait -FilePath "T:\Windows\System32\bcdboot.exe" -WorkingDirectory "T:\Windows\System32" -ArgumentList "T:\Windows /s U: /f UEFI"
    }    
    #endregion RunOnTheNewVmAndHandleDisks


    #region RunOnTheNewVmAndCheckState
    
    if ($mode -eq "CheckInternalTask") {
        if (Get-Process -Name DISM -ErrorAction SilentlyContinue) {
            # DISM is still running
            LogWriter ("Starting DISM")
        } else {
            # DISM completed to the rest and terminate
            write-host "###:COMPLETE:###"
        }
    }
    
    #endregion RunOnTheNewVmAndCheckState

#endregion MainApp



