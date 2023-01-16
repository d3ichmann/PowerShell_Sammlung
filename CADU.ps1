#*****************************************#
#                                         #
#    ░█████╗░░█████╗░██████╗░██╗░░░██╗    #
#    ██╔══██╗██╔══██╗██╔══██╗██║░░░██║    #
#    ██║░░╚═╝███████║██║░░██║██║░░░██║    #
#    ██║░░██╗██╔══██║██║░░██║██║░░░██║    #
#    ╚█████╔╝██║░░██║██████╔╝╚██████╔╝    #
#    ░╚════╝░╚═╝░░╚═╝╚═════╝░░╚═════╝░    #
#      Create Active Directory User       #
#                                         #
#*****************************************#
<#
Erforderlich für Exchange Online Powershell
- .NET Framework 4.8 - https://dotnet.microsoft.com/download/dotnet-framework/thank-you/net48-web-installer

Liste der skus - https://learn.microsoft.com/de-de/azure/active-directory/enterprise-users/licensing-service-plan-reference
- Aktuelle skus die gesucht werden in Line ~423: Microsoft 365 Business Basic=BUSINESS_ESSENTIALS, Microsoft 365 Business Standard=BUSINESS_PREMIUM, Microsoft 365 Business Premium=SPB
#>

# Wenn nicht als Admin starten
If (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    If ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
        $CommandLine = "-File `"" + $MyInvocation.MyCommand.Path + "`" " + $MyInvocation.UnboundArguments
        Start-Process -FilePath PowerShell.exe -Verb Runas -ArgumentList $CommandLine
        Exit
    }
}

# Log erstellen
$time = Get-Date -Format "dd-MM-yyyy_HH-mm-ss"
$logPath = "C:\Scripts\Create_User_Log.txt"
#Start-Transcript -Path "C:\Scripts\Create_User_Log_$time.txt"
Start-Transcript -Path $logPath -Append

Import-Module ActiveDirectory

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Domänennamen holen
$domain = (Get-WmiObject -Class Win32_ComputerSystem).Domain

# Liste der ausgefilterten Sicherheitsgruppen (Auch Domänen-Admins)
$excludeGroups = "Domänencomputer","Domänencontroller","Domänen-Admins","Domänen-Benutzer","Domänen-Gäste","Richtlinien-Ersteller-Besitzer","Schreibgeschützte Domänencontroller","Klonbare Domänencontroller","Protected Users","Schlüsseladministratoren","DnsUpdateProxy","Exchange Install Domain Servers","SophosDomainUser","SophosDomainPowerUser","SophosDomainAdministrator","Zertifikatherausgeber","RAS- und IAS-Server","Zulässige RODC-Kennwortreplikationsgruppe","Abgelehnte RODC-Kennwortreplikationsgruppe","DnsAdmins","DHCP-Benutzer","DHCP-Administratoren","WSUS Administrators","WSUS Reporters","ADSyncAdmins","ADSyncOperators","ADSyncBrowse","ADSyncPasswordSet","SophosUser","SophosPowerUser","SophosAdministrator","SophosOnAccess","SophosFimDataReaders","Administratoren","Benutzer","Gäste","Druck-Operatoren","Sicherungs-Operatoren","Replikations-Operator","Remotedesktopbenutzer","Netzwerkkonfigurations-Operatoren","Leistungsüberwachungsbenutzer","Leistungsprotokollbenutzer","Distributed COM-Benutzer","IIS_IUSRS","Kryptografie-Operatoren","Ereignisprotokollleser","Zertifikatdienst-DCOM-Zugriff","RDS-Remotezugriffsserver","RDS-Endpunktserver","RDS-Verwaltungsserver","Hyper-V-Administratoren","Zugriffssteuerungs-Unterstützungsoperatoren","Remoteverwaltungsbenutzer","System Managed Accounts Group","Storage Repl. Admin","Server-Operatoren","Konten-Operatoren","Prä-Windows 2000 kompatibler Zugriff","Erstellungen eingehender Gesamtstrukturvertrauensstellung","Windows-Autorisierungszugriffsgruppe","Terminalserver-Lizenzserver","Schema-Admins","Organisations-Admins","Schreibgeschützte Domänencontroller der Organisation","Unternehmenssschlüsseladministratoren","Organization Management","Recipient Management","View-Only Organization Management","Public Folder Management","UM Management","Help Desk","Records Management","Discovery Management","Server Management","Delegated Setup","Hygiene Management","Compliance Management","Exchange Servers","Exchange Trusted Subsystem","Managed Availability Servers","Exchange Windows Permissions","ExchangeLegacyInterop","MailStore Impersonation","Security Reader","Security Administrator","Import Export"

# Fenster erstellen
$form = New-Object System.Windows.Forms.Form
$form.Text = "Benutzer in Active Directory erstellen"
$form.Size = New-Object System.Drawing.Size(550,450)
$form.StartPosition = "CenterScreen"

# Vorname
$firstnameLabel = New-Object System.Windows.Forms.Label
$firstnameLabel.Location = New-Object System.Drawing.Size(10,20)
$firstnameLabel.Size = New-Object System.Drawing.Size(80,20)
$firstnameLabel.Text = "Vorname:"

$firstnameTextBox = New-Object System.Windows.Forms.TextBox
$firstnameTextBox.Location = New-Object System.Drawing.Size(95,20)
$firstnameTextBox.Size = New-Object System.Drawing.Size(150,20)

# Nachname
$lastnameLabel = New-Object System.Windows.Forms.Label
$lastnameLabel.Location = New-Object System.Drawing.Size(280,20)
$lastnameLabel.Size = New-Object System.Drawing.Size(80,20)
$lastnameLabel.Text = "Nachname:"

$lastnameTextBox = New-Object System.Windows.Forms.TextBox
$lastnameTextBox.Location = New-Object System.Drawing.Size(360,20)
$lastnameTextBox.Size = New-Object System.Drawing.Size(150,20)

# Benutzername
$usernameLabel = New-Object System.Windows.Forms.Label
$usernameLabel.Location = New-Object System.Drawing.Size(10,50)
$usernameLabel.Size = New-Object System.Drawing.Size(80,20)
$usernameLabel.Text = "Username:"

$usernameTextBox = New-Object System.Windows.Forms.TextBox
$usernameTextBox.Location = New-Object System.Drawing.Size(95,50)
$usernameTextBox.Size = New-Object System.Drawing.Size(150,20)

# Update Username once
$isUpdated = $false
$firstNameTextBox.Add_TextChanged({
    if (-not $isUpdated) {
        if ($lastNameTextBox.Text -eq "") {
            $usernameTextBox.Text = "$($firstNameTextBox.Text)".ToLower() -replace "ä", "ae" -replace "ü", "ue" -replace "ö", "oe" -replace "ß", "ss"
        } else {
            $usernameTextBox.Text = "$($firstNameTextBox.Text).$($lastNameTextBox.Text)".ToLower() -replace "ä", "ae" -replace "ü", "ue" -replace "ö", "oe" -replace "ß", "ss"
        }
        $isUpdated = $true
    }
})
$lastNameTextBox.Add_TextChanged({
    if (-not $isUpdated) {
        if ($firstNameTextBox.Text -eq "") {
            $usernameTextBox.Text = "$($lastNameTextBox.Text)".ToLower() -replace "ä", "ae" -replace "ü", "ue" -replace "ö", "oe" -replace "ß", "ss"
        } else {
            $usernameTextBox.Text = "$($firstNameTextBox.Text).$($lastNameTextBox.Text)".ToLower() -replace "ä", "ae" -replace "ü", "ue" -replace "ö", "oe" -replace "ß", "ss"
        }
        $isUpdated = $true
    }
})

# Passwort-Feld
$passwordLabel = New-Object System.Windows.Forms.Label
$passwordLabel.Location = New-Object System.Drawing.Size(280,50)
$passwordLabel.Size = New-Object System.Drawing.Size(80,30)
$passwordLabel.Text = "Passwort:"

$passwordTextBox = New-Object System.Windows.Forms.TextBox
$passwordTextBox.Location = New-Object System.Drawing.Size(360,50)
$passwordTextBox.Size = New-Object System.Drawing.Size(150,20)
$passwordTextBox.UseSystemPasswordChar = $true

$passwordTextBox.Add_TextChanged({
    if ($passwordTextBox.Text -ne "") {
        $createButton.Enabled = $true
        $passwordLabel.ForeColor = "Black"
        $passwordLabel.Text = "Passwort:"
    }
})

# UPN-Suffix Auswahl Feld
$upnSuffixLabel = New-Object System.Windows.Forms.Label
$upnSuffixLabel.Location = New-Object System.Drawing.Size(10, 80)
$upnSuffixLabel.Size = New-Object System.Drawing.Size(80, 20)
$upnSuffixLabel.Text = "Domain:"

$upnSuffixComboBox = New-Object System.Windows.Forms.ComboBox
$upnSuffixComboBox.Location = New-Object System.Drawing.Size(95, 80)
$upnSuffixComboBox.Size = New-Object System.Drawing.Size(150, 20)
$upnSuffixComboBox.Text = "$domain"

# UPNSuffixes auslesen
$upnSuffixes = (Get-ADForest).UPNSuffixes
$upnSuffixComboBox.Items.AddRange($upnSuffixes)

# Weitere Emailadressen Feld
$emailLabel = New-Object System.Windows.Forms.Label
$emailLabel.Location = New-Object System.Drawing.Size(280, 80)
$emailLabel.Size = New-Object System.Drawing.Size(80, 25)
$emailLabel.Text = "Weitere Email-Alias:"

$emailTextBox = New-Object System.Windows.Forms.TextBox
$emailTextBox.Location = New-Object System.Drawing.Size(360, 80)
$emailTextBox.Size = New-Object System.Drawing.Size(150, 20)

# NT-Anmeldung Feld
$samAccountNameLabel = New-Object System.Windows.Forms.Label
$samAccountNameLabel.Location = New-Object System.Drawing.Size(10, 110)
$samAccountNameLabel.Size = New-Object System.Drawing.Size(84, 20)
$samAccountNameLabel.Text = "NT-Anmeldung:"

$samAccountNameTextBox = New-Object System.Windows.Forms.TextBox
$samAccountNameTextBox.Location = New-Object System.Drawing.Size(95, 110)
$samAccountNameTextBox.Size = New-Object System.Drawing.Size(150, 20)

# Update samAccountName aus Vor- und Nachname - Sonderzeichen ersetzen
$isUpdated = $false
$firstNameTextBox.Add_TextChanged({
    if (-not $isUpdated) {
        if ($lastNameTextBox.Text -eq "") {
            $samAccountNameTextBox.Text = "$($firstNameTextBox.Text)".ToLower() -replace "ä", "ae" -replace "ü", "ue" -replace "ö", "oe" -replace "ß", "ss"
        } else {
            $samAccountNameTextBox.Text = "$($firstNameTextBox.Text).$($lastNameTextBox.Text)".ToLower() -replace "ä", "ae" -replace "ü", "ue" -replace "ö", "oe" -replace "ß", "ss"
        }
        $isUpdated = $true
    }
})
$lastNameTextBox.Add_TextChanged({
    if (-not $isUpdated) {
        if ($firstNameTextBox.Text -eq "") {
            $samAccountNameTextBox.Text = "$($lastNameTextBox.Text)".ToLower() -replace "ä", "ae" -replace "ü", "ue" -replace "ö", "oe" -replace "ß", "ss"
        } else {
            $samAccountNameTextBox.Text = "$($firstNameTextBox.Text).$($lastNameTextBox.Text)".ToLower() -replace "ä", "ae" -replace "ü", "ue" -replace "ö", "oe" -replace "ß", "ss"
        }
        $isUpdated = $true
    }
})

# OU-Feld
$ouLabel = New-Object System.Windows.Forms.Label
$ouLabel.Location = New-Object System.Drawing.Size(10,140)
$ouLabel.Size = New-Object System.Drawing.Size(80,20)
$ouLabel.Text = "Speicherort:"

$ouComboBox = New-Object System.Windows.Forms.ComboBox
$ouComboBox.Location = New-Object System.Drawing.Size(95,140)
$ouComboBox.Size = New-Object System.Drawing.Size(415,20)

# OUs auslesen und filtern
$ous = Get-ADOrganizationalUnit -Filter * | Where-Object {$_.DistinguishedName -notlike "*OU=Domain Controllers,*" -and $_.DistinguishedName -notlike "*OU=Computer*" -and $_.DistinguishedName -notlike "*OU=Server*" -and $_.DistinguishedName -notlike "*OU=Group*" -and $_.Name -notlike "*Deaktiviert*"}| Select-Object -ExpandProperty DistinguishedName
$ouComboBox.Items.AddRange($ous)

# Funktion sicheres Passwort
function ValidatePassword($password) {
    #Check if the length of the password is greater than 8 characters
    if ($password.Length -lt 8) {
        return $false
    }
    #Check if the password contains at least one uppercase letter, one lowercase letter, one digit and one non-alphanumeric character
    if (!($password -cmatch "[A-Z]") -or !($password -cmatch "[a-z]") -or !($password -cmatch "[0-9]") -or !($password -cmatch "[^a-zA-Z0-9]")) {
        return $false
    }
    #Check if the password does not contain the name of the user
    if ($password -cmatch "$username") {
        return $false
    }
    #Check if the password does not contain the name of the domain
    if ($password -cmatch "$domain") {
        return $false
    }
    #Add any additional checks here
    return $true
}

# Gruppenauswahl Feld
$groupsLabel = New-Object System.Windows.Forms.Label
$groupsLabel.Location = New-Object System.Drawing.Size(360,190)
$groupsLabel.Size = New-Object System.Drawing.Size(150,20)
$groupsLabel.Text = "Zu Gruppen hinzufügen:"

$groupsListBox = New-Object System.Windows.Forms.ListBox
$groupsListBox.Location = New-Object System.Drawing.Size(360,210)
$groupsListBox.Size = New-Object System.Drawing.Size(150,100)
$groupsListBox.SelectionMode = "MultiExtended"
$groups = Get-ADGroup -Filter {GroupCategory -eq "Security"} | Where-Object {$excludeGroups -notcontains $_.Name} | Select-Object -ExpandProperty Name
$groupsListBox.Items.AddRange($groups)

# Alle Gruppen anzeigen Checkbox
$showAllGroupsCheckBox = New-Object System.Windows.Forms.CheckBox
$showAllGroupsCheckBox.Location = New-Object System.Drawing.Size(360,310)
$showAllGroupsCheckBox.Size = New-Object System.Drawing.Size(150,20)
$showAllGroupsCheckBox.Text = "Alle Gruppen anzeigen"

#event handler for the showallgroups checkbox
$showAllGroupsCheckbox.Add_CheckedChanged({
    if($showAllGroupsCheckbox.Checked){
        $groups = Get-ADGroup -Filter * | Select-Object -ExpandProperty Name
    }
    else{
        $groups = Get-ADGroup -Filter {GroupCategory -eq "Security"} | Where-Object {$excludeGroups -notcontains $_.Name} | Select-Object -ExpandProperty Name
    }
    $groupsListBox.Items.Clear()
    $groups | ForEach-Object {
        $groupsListBox.Items.Add($_)
    }
})

#region Weitere Optionen
$optionLabel = New-Object System.Windows.Forms.Label
$optionLabel.Location = New-Object System.Drawing.Size(25,190)
$optionLabel.Size = New-Object System.Drawing.Size(100,20)
$optionLabel.Text = "Weitere Optionen"

# Kennwort bei nächster Anmeldung ändern
$changePasswordCheckbox = New-Object System.Windows.Forms.CheckBox
$changePasswordCheckbox.Location = New-Object System.Drawing.Size(25,210)
$changePasswordCheckbox.Size = New-Object System.Drawing.Size(150,27)
$changePasswordCheckbox.Text = "Kennwort bei nächster Anmeldung ändern"

$changePasswordCheckbox.Add_CheckedChanged({
    if ($changePasswordCheckbox.Checked -eq $True) {
        $passwordNeverExpiresCheckbox.Checked = $False
    }
})

# Passwort läuft nie ab Checkbox
$passwordNeverExpiresCheckbox = New-Object System.Windows.Forms.CheckBox
$passwordNeverExpiresCheckbox.Location = New-Object System.Drawing.Size(25,236)
$passwordNeverExpiresCheckbox.Size = New-Object System.Drawing.Size(150,25)
$passwordNeverExpiresCheckbox.Text = "Kennwort läuft nie ab"

$passwordNeverExpiresCheckbox.Add_CheckedChanged({
    if ($passwordNeverExpiresCheckbox.Checked -eq $True) {
        $changePasswordCheckbox.Checked = $False
    }
})

# Azure AD sync Checkbox
$azureSyncCheckbox = New-Object System.Windows.Forms.CheckBox
$azureSyncCheckbox.Location = New-Object System.Drawing.Size(25, 260)
$azureSyncCheckbox.Size = New-Object System.Drawing.Size(150,25)
$azureSyncCheckbox.Text = "Sync mit Azure AD"

# Azure AD Sync OUs wählen
$azureSyncCheckbox.Add_CheckedChanged({
    # Abgleich der AzureADSync OUs
    $AADConnector= “$domain”
    $AADConn= Get-ADSyncConnector -Name $AADConnector
    $AADConPartition = Get-ADSyncConnectorPartition -Connector $AADConn[0] -Identifier $AADConn.Partitions.Identifier.Guid
    $AADous = $AADConPartition.ConnectorPartitionScope.ContainerInclusionList
    if($azureSyncCheckbox.Checked){
        $ouComboBox.Items.Clear()
        $ouComboBox.Items.AddRange($AADous)
        $ouComboBox.SelectedIndex = 0
    }else{
        $ouComboBox.Items.Clear()
        $ouComboBox.Items.AddRange($ous)
        $ouComboBox.SelectedIndex = -1
        $ouComboBox.Text = ""
    }
})

# Homedrive Checkbox
$homeDriveCheckbox = New-Object System.Windows.Forms.CheckBox
$homeDriveCheckbox.Location = New-Object System.Drawing.Size(25, 280)
$homeDriveCheckbox.Size = New-Object System.Drawing.Size(150, 30)
$homeDriveCheckbox.Text = "Usershare hinzufügen"

$homeDriveCheckbox.Add_CheckedChanged({
    if ($homeDriveCheckbox.Checked) {
        $driveLetterComboBox.Enabled = $true
        $homeDrivePathTextBox.Enabled = $true
    } else {
        $driveLetterComboBox.Enabled = $false
        $homeDrivePathTextBox.Enabled = $false
    }
})

# Text für Usershare
$homeDrivePathLabel = New-Object System.Windows.Forms.Label
$homeDrivePathLabel.Location = New-Object System.Drawing.Size(25, 310)
$homeDrivePathLabel.Size = New-Object System.Drawing.Size(150, 20)
$homeDrivePathLabel.Text = "Buchstabe und Pfad:"

# Laufwerksbuchstaben wählen
$driveLetterComboBox = New-Object System.Windows.Forms.ComboBox
$driveLetterComboBox.Location = New-Object System.Drawing.Size(23, 330)
$driveLetterComboBox.Size = New-Object System.Drawing.Size(35, 20)
$driveLetterComboBox.Items.AddRange(("D:", "E:", "F:", "G:", "H:", "I:", "J:", "K:", "L:", "M:", "N:", "O:", "P:", "Q:", "R:", "S:", "T:", "U:", "V:", "W:", "X:", "Y:", "Z:"))
$driveLetterComboBox.SelectedIndex = 17
$driveLetterComboBox.Enabled = $false

# Pfad für das Homedrive
$homeDrivePathTextBox = New-Object System.Windows.Forms.TextBox
$homeDrivePathTextBox.Location = New-Object System.Drawing.Size(60, 330)
$homeDrivePathTextBox.Size = New-Object System.Drawing.Size(100, 20)
$homeDrivePathTextBox.Enabled = $false
#endregion

#region Office 365 Optionen
$o365OptionLabel = New-Object System.Windows.Forms.Label
$o365OptionLabel.Location = New-Object System.Drawing.Size(190,190)
$o365OptionLabel.Size = New-Object System.Drawing.Size(150,20)
$o365OptionLabel.Text = "Office 365 Optionen"

# Lizenz-Feld
$licenseLabel = New-Object System.Windows.Forms.Label
$licenseLabel.Location = New-Object System.Drawing.Size(190,240)
$licenseLabel.Size = New-Object System.Drawing.Size(100,20)
$licenseLabel.Text = "Lizenzauswahl:"

$licenseComboBox = New-Object System.Windows.Forms.ComboBox
$licenseComboBox.Location = New-Object System.Drawing.Size(190,260)
$licenseComboBox.Size = New-Object System.Drawing.Size(150,20)
$licenseComboBox.Enabled = $false

#endregion

#region Tooltips
$toolTip = New-Object System.Windows.Forms.ToolTip
$toolTip.SetToolTip($passwordTextBox, "Mindestens 8 Zeichen und komplex")
$toolTip.SetToolTip($emailTextBox, "Mehrere Adressen mit ';' trennen")
$toolTip.SetToolTip($ouComboBox, "Wenn nichts ausgewählt, wird der Benutzer unter Users erstellt")
$toolTip.SetToolTip($groupsListBox, "Mehrfachauswahl erfolgt mit STRG")
#endregion

#region Buttons
# Connect AzureAD Button erstellen
$connectAadButton = New-Object System.Windows.Forms.Button
$connectAadButton.Location = New-Object System.Drawing.Size(190,210)
$connectAadButton.Size = New-Object System.Drawing.Size(130,23)
$connectAadButton.Text = "Mit AzureAD verbinden"

$connectAadButton.Add_Click({
    $licenseComboBox.Enabled = $true
    $azureSyncCheckbox.Checked = $true
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if (Get-Module -Name MSOnline -ListAvailable) {
    } else {
        Install-Module -Name MSOnline -Force
    }
    # Verbindung mit O365 herstellen
    $AADsession = New-PSSession
    Import-Module -Name MSOnline
    Enter-PSSession $AADsession
    Connect-MsolService
    # Alle Verfügbaren Lizenzen anzeigen
    $licenses = Get-MsolAccountSku | Select-Object -Property AccountSkuId, ActiveUnits, ConsumedUnits
    $licenses | where {$_.AccountSkuId -like '*BUSINESS_PREMIUM' -or $_.AccountSkuId -like '*BUSINESS_ESSENTIALS' -or $_.AccountSkuId -like '*SPB'} | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name AvailableUnits -Value ($_.ActiveUnits - $_.ConsumedUnits)}
    $licenses = $licenses | where {$_.AvailableUnits -gt 0}
    foreach ($item in $licenses){
        #$licenseComboBox.Items.Add("$($item.AccountSkuId) - $($item.AvailableUnits)")
        $licenseComboBox.Items.Add("$($item.AccountSkuId)")
    }
})

# Connect EXO Button
$connectEXOButton = New-Object System.Windows.Forms.Button
$connectEXOButton.Location = New-Object System.Drawing.Size(190,295)
$connectEXOButton.Size = New-Object System.Drawing.Size(130,23)
$connectEXOButton.Text = "Mit EXO verbinden"
$connectEXOButton.Enabled = $false

$connectAadButton.Add_Click({
    $azureSyncCheckbox.Checked = $true
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    if (!(Get-Module -Name "ExchangeOnlineManagement")){
        Install-Module -Name ExchangeOnlineManagement -Force
    }
    # Verbindung mit EXO herstellen
    Import-Module -Name ExchangeOnlineManagement
    $EXOsession = New-PSSession
    Enter-PSSession $EXOsession
    Connect-ExchangeOnline
})

# Erstellen-Button erstellen
$createButton = New-Object System.Windows.Forms.Button
$createButton.Location = New-Object System.Drawing.Size(180,370)
$createButton.Size = New-Object System.Drawing.Size(75,23)
$createButton.Text = "Erstellen"

$createButton.Add_Click({
    $firstname = $firstnameTextBox.Text
    $lastname = $lastnameTextBox.Text
    $username = $usernameTextBox.Text
    $samAccountName = $samAccountNameTextBox.Text
    if ($upnSuffixComboBox.SelectedItem -eq $null) {
        $upnSuffix = "$domain"
    } else {
        $upnSuffix = $upnSuffixComboBox.SelectedItem
    }
    $password = $passwordTextBox.Text
    $ou = $ouComboBox.SelectedItem
    # Wenn Passwortfeld leer Warnung
    if ($passwordTextBox.Text -eq "") {
        $createButton.Enabled = $false
        $passwordLabel.ForeColor = "Red"
        $passwordLabel.Text = "Passwort:"
    } else {
        if (ValidatePassword($passwordTextBox.Text)) {
        # Benutzer erstellen
        if ($ou -eq $null) {
            New-ADUser -Name "$firstname $lastname" -DisplayName "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $samAccountName -UserPrincipalName "$username@$upnSuffix" -EmailAddress "$username@$upnSuffix" -AccountPassword (ConvertTo-SecureString $passwordTextBox.Text -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $passwordNeverExpiresCheckbox.Checked
        } else {
            New-ADUser -Name "$firstname $lastname" -DisplayName "$firstname $lastname" -GivenName $firstname -Surname $lastname -SamAccountName $samAccountName -UserPrincipalName "$username@$upnSuffix" -EmailAddress "$username@$upnSuffix" -AccountPassword (ConvertTo-SecureString $passwordTextBox.Text -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $passwordNeverExpiresCheckbox.Checked -Path $ou
        }
        # Prüfen ob der Benutzer erstellt wurde
        $user = Get-ADUser -Identity $samAccountName -ErrorAction SilentlyContinue
        if ($user) {
            # UPN als Hauptmailadresse
            Set-ADUser -Identity $samAccountName -Add @{proxyAddresses="SMTP:$username@$upnSuffix"}
            # Weitere Mailadressen zum proxyaddresses-Attribut hinzufügen
            if ($emailTextBox.Text -ne "") {
                if ($emailTextBox.Text.EndsWith(";")) {
                    $emailTextBox.Text = $emailTextBox.Text.Remove($emailTextBox.Text.Length - 1)
                }
                $emailArray = $emailTextBox.Text -split ";"
                foreach ($email in $emailArray) {
                    Set-ADUser -Identity $samAccountName -Add @{proxyAddresses=("smtp:$email")}
                }
            }
            # Passwort bei nächer Anmeldung ändern
            if ($changePasswordCheckbox.Checked) {
            Set-ADUser -Identity $samAccountName -ChangePasswordAtLogon $true
            }
            # Benutzer zu ausgewählten Gruppen hinzufügen
            foreach ($group in $groupsListBox.SelectedItems) {
                Add-ADGroupMember -Identity $group -Members $samAccountName
            }
            # Usershare hinzufügen
            if ($homedriveCheckbox.Checked -eq $True) {
                $driveLetter = $driveLetterComboBox.SelectedItem
                $drivePath = $homeDrivePathTextBox.Text
                if ($drivePath.Substring($drivePath.Length - 1) -ne "\") {
                    $drivePath = $drivePath + "\" + $samAccountName
                } else {
                    $drivePath = $drivePath + $samAccountName
                }
                Set-ADUser -Identity $samAccountName -HomeDrive $driveLetter -HomeDirectory $drivePath
            }
            Add-Type -AssemblyName System.Windows.Forms
            [System.Windows.Forms.MessageBox]::Show("Benutzer $samAccountName wurde erfolgreich erstellt", "Erfolgreich", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
            Write-Host "$time Benutzer wurde erfolgreich erstellt"
            # Wenn Azure ADSync ausgewählt - sync starten
            if ($azureSyncCheckbox.Checked -eq $True) {
                Start-AdSyncSyncCycle -PolicyType Delta
                Write-Host "$time Azure AD Sync wurde gestartet"
            }
            # Lizenz zuweisen
            if ($licenseComboBox.Enabled -eq $True) {
                if ($licenseComboBox.SelectedItem -eq $null -or $licenseComboBox.SelectedItem -eq "") {
                    [System.Windows.Forms.MessageBox]::Show("Please get a new license from Crayon", "Keine freie Lizenz vorhanden", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning)
                    $counter = 0
                    $maxIterations = 60 # Number of iterations before canceling the loop
                    $continueLoop = $True
                    # Warten bis eine Lizenz hinzugefügt wurde
                    while ($licenseComboBox.SelectedItem -eq $null -or $licenseComboBox.SelectedItem -eq "" -and $continueLoop -eq $True) {
                        $licenses = Get-MsolAccountSku | Select-Object -Property AccountSkuId, ActiveUnits, ConsumedUnits
                        $licenses | where {$_.AccountSkuId -like '*BUSINESS_PREMIUM' -or $_.AccountSkuId -like '*BUSINESS_ESSENTIALS' -or $_.AccountSkuId -like '*SPB'} | ForEach-Object {$_ | Add-Member -MemberType NoteProperty -Name AvailableUnits -Value ($_.ActiveUnits - $_.ConsumedUnits)}
                        $licenses = $licenses | where {$_.AvailableUnits -gt 0}
                        $licenseComboBox.Items.Clear()
                        foreach ($item in $licenses){
                            $licenseComboBox.Items.Add("$($item.AccountSkuId) - $($item.AvailableUnits)")
                        }
                        Start-Sleep -Seconds 10
                        $counter++
                        if ($counter -ge $maxIterations) {
                            [System.Windows.Forms.MessageBox]::Show("No available licenses found within 5 minutes, please check the status of the licenses", "License Timeout", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                            $continueLoop = $False
                        }
                    }
                } else {
                # Warten bis der Benutzer gesynct wurde, nach 1 Minuten wird abgebrochen
                $synced = $false
                $counter = 0
                $timeout = 60 # 1 minutes in seconds
                while ($synced -eq $false) {
                    $365user = Get-MsolUser -UserPrincipalName "$username@$upnSuffix" -ErrorAction SilentlyContinue
                    if ($365user) {
                        if ($365user.IsLicensed -eq $True) {
                            $synced = $true
                        }
                    }
                    Start-Sleep -Seconds 10
                    Write-Host "$time Warte bis Benutzer synchronisiert wurde..."
                    $counter++
                    if ($counter -ge $timeout) {
                        [System.Windows.Forms.MessageBox]::Show("User was not synced within 1 minutes, please check the status of the synchronization", "Sync Timeout", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
                        break
                    }
                    $selectedLicense = $licenseComboBox.SelectedItem.Split(" ")[0]
                    Set-MsolUser -UserPrincipalName "$username@$upnSuffix" -UsageLocation "DE" -ErrorAction SilentlyContinue
                    Set-MsolUserLicense -UserPrincipalName "$username@$upnSuffix" -AddLicenses $selectedLicense  -ErrorAction SilentlyContinue
                }
                }
            }
            if ($mailOptionCheckbox.Checked -eq $True) {
            }
            # Alle Felder zurücksetzen
            $firstnameTextBox.Text = ""
            $lastnameTextBox.Text = ""
            $usernameTextBox.Text = ""
            $upnSuffixComboBox.SelectedItem = $null
            $passwordTextBox.Text = ""
            $samAccountNameTextBox.Text = ""
            $ouComboBox.SelectedItem = $null
            $emailTextBox.Text = ""
            $passwordNeverExpiresCheckbox.Checked = $false
            $azureSyncCheckbox.Checked = $false
            $homeDriveCheckbox.Checked = $false
            $homeDrivePathTextBox.Text = ""
            $licenseComboBox.Enabled = $false
            $showAllGroupsCheckBox.Checked = $false
            $groupsListBox.ClearSelected()
         } else {
                [System.Windows.Forms.MessageBox]::Show("Ein Fehler ist aufgetreten. Bitte prüfe den die Log-Information unter $logPath", "Fehler", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
            }
        } else {
            $passwordLabel.ForeColor = "Red"
            $passwordLabel.Text = "Passwort nicht sicher!"
        }
    }
})

# Button-Schliessen erstellen
$closeButton = New-Object System.Windows.Forms.Button
$closeButton.Location = New-Object System.Drawing.Size(280,370)
$closeButton.Size = New-Object System.Drawing.Size(75,23)
$closeButton.Text = "Schliessen"

$closeButton.Add_Click({
    if ($mailOptionCheckbox.Checked -eq $True) {
        Exit-PSSession $EXOsession
        Write-Host "$time EXOsession wurde beendet"
    }
    if ($licenseComboBox.Enabled -eq $True) {
        Exit-PSSession $AADsession
        Write-Host "$time AADsession wurde beendet"
    }
$form.Close()
})
#endregion

#region Add to Form
$form.Controls.Add($firstnameLabel)
$form.Controls.Add($firstnameTextBox)
$form.Controls.Add($lastnameLabel)
$form.Controls.Add($lastnameTextBox)
$form.Controls.Add($usernameLabel)
$form.Controls.Add($usernameTextBox)
$form.Controls.Add($passwordLabel)
$form.Controls.Add($passwordTextBox)
$form.Controls.Add($upnSuffixLabel)
$form.Controls.Add($upnSuffixComboBox)
$form.Controls.Add($emailLabel)
$form.Controls.Add($emailTextBox)
$form.Controls.Add($samAccountNameLabel)
$form.Controls.Add($samAccountNameTextBox)
$form.Controls.Add($ouLabel)
$form.Controls.Add($ouComboBox)
$form.Controls.Add($groupsLabel)
$form.Controls.Add($groupsListBox)
$form.Controls.Add($showAllGroupsCheckBox)
$form.Controls.Add($optionLabel)
$form.Controls.Add($changePasswordCheckbox)
$form.Controls.Add($passwordNeverExpiresCheckbox)
$form.Controls.Add($azureSyncCheckbox)
$form.Controls.Add($homeDriveCheckbox)
$form.Controls.Add($driveLetterComboBox)
$form.Controls.Add($homeDrivePathLabel)
$form.Controls.Add($homeDrivePathTextBox)
$form.Controls.Add($o365OptionLabel)
$form.Controls.Add($connectAadButton)
$form.Controls.Add($licenseLabel)
$form.Controls.Add($licenseComboBox)
$form.Controls.Add($connectEXOButton)
$form.Controls.Add($createButton)
$form.Controls.Add($closeButton)
$form.ShowDialog()
#endregion

# Log Ende
Stop-Transcript
