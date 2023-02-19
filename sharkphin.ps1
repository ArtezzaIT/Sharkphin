#    Aretzza Sharkphin - Phishing Response Tool
#    Copyright (C) 2022  Benjamin Jaros and Madeline Susemiehl
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as published
#    by the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <https://www.gnu.org/licenses/>.

$version = "0.3.0"
$channel = "stable"

write-host "        ______     ______     ______   ______     ______     ______     ______                "
write-host "       /\  __ \   /\  == \   /\__  _\ /\  ___\   /\___  \   /\___  \   /\  __ \               "
write-host "       \ \  __ \  \ \  __<   \/_/\ \/ \ \  __\   \/_/  /__  \/_/  /__  \ \  __ \              "
write-host "        \ \_\ \_\  \ \_\ \_\    \ \_\  \ \_____\   /\_____\   /\_____\  \ \_\ \_\             "
write-host "         \/_/\/_/   \/_/ /_/     \/_/   \/_____/   \/_____/   \/_____/   \/_/\/_/             "
write-host "                                                                                              "
write-host " ______     __  __     ______     ______     __  __     ______   __  __     __     __   __    "
write-host "/\  ___\   /\ \_\ \   /\  __ \   /\  == \   /\ \/ /    /\  == \ /\ \_\ \   /\ \   /\ `"-.\ \   "
write-host "\ \___  \  \ \  __ \  \ \  __ \  \ \  __<   \ \  _`"-.  \ \  _-/ \ \  __ \  \ \ \  \ \ \-.  \  "
write-host " \/\_____\  \ \_\ \_\  \ \_\ \_\  \ \_\ \_\  \ \_\ \_\  \ \_\    \ \_\ \_\  \ \_\  \ \_\\`"\_\ "
write-host "  \/_____/   \/_/\/_/   \/_/\/_/   \/_/ /_/   \/_/\/_/   \/_/     \/_/\/_/   \/_/   \/_/ \/_/ "
write-host "                                                                                              "

Write-Host "Written by Benjamin and Madeline"
Write-Host "Version $version, $channel channel"

#Check if running the latest/recommended version
try {
    $availableonline = (invoke-webrequest -uri https://sharkphin.artezza.io/latest.json -usebasicparsing).content | ConvertFrom-Json
    if ($availableonline.$channel[0] -ne $version){
        Write-host "You are not running the recommended version for the $channel channel!"
        $updatechoice = Read-Host "Would you like to download the recommended verion? (y/N)"
        if ($updatechoice.ToLower() -eq "y"){
            $downloadlnk = $availableonline.$channel[1]
            cmd /c "START $downloadlnk"
            exit
        }
    } else {
        Write-Host "This version is up to date! You're running $version, $channel"
    }
}
catch {
    Write-Host "There was an error checking for updates. You can always check for new versions at https://sharkphin.artezza.io"
}

#Setup dependancies
try {
    #Install EXO module if missing
    Install-Module -Name ExchangeOnlineManagement
    #Update to latest version
    Update-Module -Name ExchangeOnlineManagement
}
catch {
    Write-Output "An error occurred installing or updating the Exchange Online module. Usually this can be resolved by launching the program as administrator."
    Write-Output "Attempting to continue without updating..."
}


#Connect to Security & Compliance PowerShell, then Exchange Online
try{
    Import-Module ExchangeOnlineManagement
    Connect-IPPSSession
    Connect-ExchangeOnline -ShowBanner:$false
}
catch {
    Write-Host "There was an error signing into the 365 tenant. Please verify the credentials you are using are correct and that the Exchange Online Module is installed."
    Read-Host "Press enter to close."
    Disconnect-ExchangeOnline -Confirm:$false
    exit
}

function CheckSearchStatus {
    #Function to wait for search to complete
    param (
        $SearchName
    )
    #FGet search and status
    $SearchStatus = Get-ComplianceSearch -Identity $SearchName | Select-Object -Property Status
    if ($SearchStatus.Status -ne "Completed"){
        #if not complete, print status
        Write-Host "Search not yet complete... Current status:", $SearchStatus.Status
        #wait 15 seconds
        Start-Sleep -Seconds 15
        #do it again
        CheckSearchStatus $SearchName
    }
    else {
        Write-Host "Search complete!"
    }
}
function Get-SearchFromUser {

    #Prompt user to enter parameters for content search
    $ContentSearchName=Read-Host -Prompt "Enter Unique Content Search Name"
    $InputPhishSenderName=Read-Host -Prompt "Enter the full email address of the phisher"
    $InputPhishSubject=Read-Host -Prompt "Enter the exact subject of the phish"

    #make "" into '' because KQL is weird
    $InputPhishSubject = $InputPhishSubject.Replace('"', "'")
    #Escape quotes for KQL query string
    $InputPhishSubject = $InputPhishSubject.Replace("'","''")

	#Combine the email address and the subject into one string
    $InputMatchQuery="(From:"+$InputPhishSenderName+") AND (Subject:`""+$InputPhishSubject+"`")"

    Write-Host "Building search..."

    #Create a Content Search to find the message
    $Search=New-ComplianceSearch -Name $ContentSearchName -ExchangeLocation All -ContentMatchQuery $InputMatchQuery


    #Start Content Search
    Start-ComplianceSearch -Identity $Search.Identity

    #ADD running search message
    Write-Output "Content Search is running. Please wait..."

    #Wait to continue to allow Content Search to finish
    CheckSearchStatus $ContentSearchName

    #Return the ContentSearchName variable for the soft delete loop below 
    Set-Variable -Name "ContentSearchName" -Value $ContentSearchName -scope global
    Set-Variable -Name "PhishSenderName" -Value $InputPhishSenderName -scope global

    #System message to tell them to review number before deleting 
    Write-Output "Review number of items found in Content Search. Items should be greater than 0."

    #Confirm number of items found from the search
    Get-ComplianceSearch -Identity $ContentSearchName | Select-Object -Property Name, Items | Format-Table -AutoSize

    
}
function SearchAndPurge {
    Get-SearchFromUser
    #SOFT DELETE SECTION
    #Loop for user input to confirm deleting
    do {
        $response = Read-Host -Prompt "Are you ready to remove these items from all inboxes? (Y/N)"
        $response = $response.ToLower()
        if ($response -eq 'y') {
            New-ComplianceSearchAction -SearchName $ContentSearchName -Purge -PurgeType SoftDelete
            break
        }
    } until (
        ($response -eq 'n')
    )
    BlockThem $PhishSenderName
}
function BlockThem {
    param (
        $email
    )
    #get phish domain
    $phishdomain = $email.substring($email.indexof("@")+1)
    #Loop asking to block domain/email
    do {
        $response = Read-Host -Prompt "Would you like to mark the entire $phishdomain domain as spam in this tenant? (Y/N)"
        $response = $response.ToLower()
        if ($response -eq 'y') {
            New-TenantAllowBlockListItems -ListType Sender -Block -Entries $phishdomain -NoExpiration
            break
        }
        else{
            #Loop asking to block domain/email
            do {
                $response = Read-Host -Prompt "Would you like to mark the specific email address $email as spam within this tenant? (Y/N)"
                $response = $response.ToLower()
                if ($response -eq 'y') {
                    New-TenantAllowBlockListItems -ListType Sender -Block -Entries $email -NoExpiration
                    break
                }
            } until (
                ($response -eq 'n')
            )
            break
                }
    } until (
        ($response -eq 'n')
    )
}
function main_menu {
    Write-Host "========================="
    Write-Host "1. Search and Purge mail"
    Write-Host "2. Block email and/or domain"
    Write-Host "3. Exit"
    $selection = Read-Host "Select a number from the menu"
    if ($selection -eq "1"){
        SearchAndPurge
        main_menu
    }elseif ($selection -eq "2") {
        $email = Read-Host "Enter an email address"
        BlockThem $email
        main_menu
    }elseif ($selection -eq "3"){
        #Disconnect from session 
        Disconnect-ExchangeOnline -Confirm:$false

        #Message: Disconnected successfully, you can close window
        Read-Host "Session disconnected successfully. Hit enter to close"
        exit
    }else {
        Write-Host "Sorry! That option wasn't understood. Please try again."
        main_menu
    }
}

main_menu