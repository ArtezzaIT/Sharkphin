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

#Function definitions

#Create new search in 365
function New-CustomSearch {
    param (
        [string]$ContentSearchName,
        [string]$InputPhishSenderName,
        [string]$InputPhishSubject
    )

    #make "" into '' because KQL is weird
    $InputPhishSubject = $InputPhishSubject.Replace('"', "'")
    #Escape quotes for KQL query string
    $InputPhishSubject = $InputPhishSubject.Replace("'","''")

	#Combine the email address and the subject into one string
    $InputMatchQuery="(From:"+$InputPhishSenderName+") AND (Subject:`""+$InputPhishSubject+"`")"

    Write-Host "Building search $ContentSearchName..."

    #Create a Content Search to find the message
    try{
        $Search=New-ComplianceSearch -Name $ContentSearchName -ExchangeLocation All -ContentMatchQuery $InputMatchQuery
    } catch {
        #If the search fails, cut back to the main menu.
        Write-Host "There was an error creating the content search in 365. The search query generated was:"
        Write-Host $InputMatchQuery
        Write-Host "Please consider reporting an issue at https://github.com/ArtezzaIT/Sharkphin/issues"
        return "There was an error creating the content search in 365. The search query generated was: $InputMatchQuery"
    }

    #Start Content Search
    Start-ComplianceSearch -Identity $Search.Identity

    #ADD running search message
    Write-Host "Content Search is running. Please check the Sharkphin or Purview portal for status."
    return "The content search ##SEARCHNAME## was successfully submitted as ##UPN##. Please check the Sharkphin or Purview portal for status."
}

# Function to parse query string into a hashtable
function Parse-QueryString {
    param (
        [string]$queryString
    )
    $queryParams = @{}
    if ($queryString) {
        $queryString -split "&" | ForEach-Object {
            $paramParts = $_ -split "="
            $queryParams[$paramParts[0]] = [System.Web.HttpUtility]::UrlDecode($paramParts[1])
        }
    }
    return $queryParams
}

#Program initialization
$version = "0.4.1"
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

#Check platform. These are built-in variables in PS 6+. Below PS6 we assume Windows only.
if ($PSVersionTable.PSVersion.Major -lt 6) {
    # Code to run if PowerShell version is below 6
    Write-Host "Running on PowerShell version below 6"
    $IsWindows = $true
    $IsMacOS = $false
    $IsLinux = $false
}


#Check if running the latest/recommended version
try {
    $availableonline = (Invoke-WebRequest -uri https://sharkphin.artezza.io/latest.json -usebasicparsing).content | ConvertFrom-Json
    if ($availableonline.$channel[0] -ne $version){
        Write-host "You are not running the recommended version for the $channel channel!"
        $updatechoice = Read-Host "Would you like to download the recommended verion? (y/N)"
        if ($updatechoice.ToLower() -eq "y"){
            $downloadlnk = $availableonline.$channel[1]
            if ($IsWindows) {
                Start-Process $downloadlnk
            } elseif ($IsMacOS) {
                Start-Process "open" -ArgumentList $downloadlnk
            } elseif ($IsLinux) {
                Start-Process "xdg-open" -ArgumentList $downloadlnk
            }
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
Write-Host "Setting up modules..."
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
Write-Host "Connecting to 365..."
try{
    Import-Module ExchangeOnlineManagement
    Connect-IPPSSession -EnableSeachOnlySession -ShowBanner:$false
    $UPN = (Get-ConnectionInformation).UserPrincipalName
    Connect-ExchangeOnline -ShowBanner:$false -UserPrincipalName $UPN
}
catch {
    Write-Host "There was an error signing into the 365 tenant. Please verify the credentials you are using are correct and that the Exchange Online Module is installed (running as admin may fix this problem)."
    Read-Host "Press enter to close."
    Disconnect-ExchangeOnline -Confirm:$false
    exit
}

#Server setup
Write-Host "Starting server..."
$port = 8080
$listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $port)
$listener.Start()
$portal = "http://localhost:$port/"
Write-Host "Server running on $portal/"
if ($IsWindows) {
    Start-Process $portal
} elseif ($IsMacOS) {
    Start-Process "open" -ArgumentList $portal
} elseif ($IsLinux) {
    Start-Process "xdg-open" -ArgumentList $portal
}


#Request loop
$activeSession = $true
while ($activeSession) {
    #Accept request
    $client = $listener.AcceptTcpClient()
    $stream = $client.GetStream()
    $reader = New-Object System.IO.StreamReader($stream)
    $request = $reader.ReadLine()

    Write-Host "Received request: $request"

    # Parse the request to get the requested page and query parameters
    $pageRequest = $request -split " " | Select-Object -Index 1
    $pageRequestParts = $pageRequest -split "\?"
    $pagePath = $pageRequestParts[0]
    $queryString = if ($pageRequestParts.Count -gt 1) { $pageRequestParts[1] } else { "" }
    $queryParams = Parse-QueryString -queryString $queryString

    Write-Host $queryParams

    switch ($pagePath) {
        "/" {
            # Default page, do nothing special
            $htmlFilePath = "$PSScriptRoot\app.html"
            $htmlContent = Get-Content -Path $htmlFilePath -Raw
            $htmlContent =  $htmlContent -replace "##UPN##", $UPN
            $response = "HTTP/1.1 200 OK`r`nContent-Type: text/html`r`n`r`n$htmlContent"
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($response)
        }
        "/favicon.ico" {
            # Handle favicon request
            $faviconPath = "$PSScriptRoot/favicon.ico"
            $faviconContent = [System.IO.File]::ReadAllBytes($faviconPath)
            $response = "HTTP/1.1 200 OK`r`nContent-Type: image/x-icon`r`n`r`n"
            $buffer = [System.Text.Encoding]::ASCII.GetBytes($response) + $faviconContent
        }
        "/background.jpg" {
            # Handle background request
            $backgroundPath = "$PSScriptRoot/background.jpg"
            $backgroundContent = [System.IO.File]::ReadAllBytes($backgroundPath)
            $response = "HTTP/1.1 200 OK`r`nContent-Type: image/jpg`r`n`r`n"
            $buffer = [System.Text.Encoding]::ASCII.GetBytes($response) + $backgroundContent
        }
        "/logout" {
            # Handle logout page request
            Write-Host "Handling logout request"
            $htmlFilePath = "$PSScriptRoot\logout.html"
            $activeSession = $false
            $htmlContent = Get-Content -Path $htmlFilePath -Raw
            $response = "HTTP/1.1 200 OK`r`nContent-Type: text/html`r`n`r`n$htmlContent"
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($response)
        }
        "/search" {
            # Handle search page request
            Write-Host "Handling search request"
            # Extract search query parameters
            $searchName = $queryParams["name"]
            $phishSenderName = $queryParams["sender"]
            $phishSubject = $queryParams["subject"]

            # Perform search operation
            if ($searchName -and $phishSenderName -and $phishSubject) {
                $resultMessage = New-CustomSearch -ContentSearchName $searchName -InputPhishSenderName $phishSenderName -InputPhishSubject $phishSubject
                $htmlFilePath = "$PSScriptRoot\search.html"
                $htmlContent = Get-Content -Path $htmlFilePath -Raw
                $htmlContent =  $htmlContent -replace "##RESULTMESSAGE##", $resultMessage
                $htmlContent =  $htmlContent -replace "##UPN##", $UPN
                $htmlContent =  $htmlContent -replace "##SEARCHNAME##", $searchName
                $response = "HTTP/1.1 200 OK`r`nContent-Type: text/html`r`n`r`n$htmlContent"
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($response)
            } else {
                $htmlFilePath = "$PSScriptRoot\400.html"
                $htmlContent = Get-Content -Path $htmlFilePath -Raw
                $response = "HTTP/1.1 400 Bad Request`r`nContent-Type: text/html`r`n`r`n$htmlContent"
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($response)
            }
        }
        "/searchstatus" {
            # Return JSON string of compliance search information
            Write-Host "Handling search status request"
            $searches = @()
            $availableSearches = Get-ComplianceSearch
            foreach ($search in $availableSearches){
                $searchData = Get-ComplianceSearch -Identity $search.Identity | Select-Object -Property Name, Items, Status
                $searches += $searchData
            }
            if ($searches.Count -eq 0) {
                $searches = @{"Message" = "No searches found."}
            }
            # Convert the search data to JSON
            $searchesJson = $searches | ConvertTo-Json
            $response = "HTTP/1.1 200 OK`r`nContent-Type: application/json`r`n`r`n$searchesJson"
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($response)
        }
        "/delete" {
            # Delete a compliance search
            Write-Host "Handling delete search request"
            $searchName = $queryParams["name"]
            if ($searchName) {
                try {
                    Remove-ComplianceSearch -Identity $searchName -Confirm:$false
                    $answer = "Search $searchName deleted successfully"
                }
                catch {
                    $answer = "Error deleting search $searchName"
                }
                $response = "HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`n`r`n$answer"
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($response)
            } else {
                $htmlFilePath = "$PSScriptRoot\400.html"
                $htmlContent = Get-Content -Path $htmlFilePath -Raw
                $response = "HTTP/1.1 400 Bad Request`r`nContent-Type: text/html`r`n`r`n$htmlContent"
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($response)
            }
        }
        "/purge" {
            # Delete a compliance search
            Write-Host "Handling purge search request"
            $searchName = $queryParams["name"]
            if ($searchName) {
                try {
                    New-ComplianceSearchAction -SearchName $searchName -Purge -PurgeType SoftDelete -Confirm:$false
                    $answer = "Search $searchName purging successfully"
                }
                catch {
                    $answer = "Error purging search $searchName"
                }
                $response = "HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`n`r`n$answer"
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($response)
            } else {
                $htmlFilePath = "$PSScriptRoot\400.html"
                $htmlContent = Get-Content -Path $htmlFilePath -Raw
                $response = "HTTP/1.1 400 Bad Request`r`nContent-Type: text/html`r`n`r`n$htmlContent"
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($response)
            }
        }
        "/restart" {
            # Restart a compliance search
            Write-Host "Handling restart search request"
            $searchName = $queryParams["name"]
            if ($searchName) {
                try {
                    Start-ComplianceSearch -Identity $searchName
                    $answer = "Search $searchName restarted successfully"
                }
                catch {
                    $answer = "Error restarting search $searchName"
                }
                $response = "HTTP/1.1 200 OK`r`nContent-Type: text/plain`r`n`r`n$answer"
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($response)
            } else {
                $htmlFilePath = "$PSScriptRoot\400.html"
                $htmlContent = Get-Content -Path $htmlFilePath -Raw
                $response = "HTTP/1.1 400 Bad Request`r`nContent-Type: text/html`r`n`r`n$htmlContent"
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($response)
            }
        }
        default {
            # Handle unknown page request
            Write-Host "Unknown page request: $pageRequest"
            $htmlFilePath = "$PSScriptRoot\404.html"
            $htmlContent = Get-Content -Path $htmlFilePath -Raw
            $response = "HTTP/1.1 200 OK`r`nContent-Type: text/html`r`n`r`n$htmlContent"
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($response)
        }
    }

    $stream.Write($buffer, 0, $buffer.Length)
    $stream.Close()
    $client.Close()
}

#Cleanup
Write-Host "Logging out and ending processes..."
$listener.Stop()
Disconnect-ExchangeOnline -Confirm:$false
Read-Host "Session disconnected successfully. Hit enter to close"
