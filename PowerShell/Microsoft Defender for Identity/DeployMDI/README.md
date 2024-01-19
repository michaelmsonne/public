# This is used to deploy GPO´s for your deployment of MDI

### Readme for MDI Deployment Scripts

# Instructions for Using PowerShell Console as an Administrator

1. **Open PowerShell as an Administrator:**
   - Right-click on the PowerShell icon.
   - Select "Run as administrator" from the context menu.

2. **Enable Script Execution:**
   - To allow script execution, set the execution policy. Run the following command:
     ```powershell
     Set-ExecutionPolicy RemoteSigned
     ```
     Choose 'Y' when prompted to confirm.

3. **Navigate to the Script Directory:**
   - Change the current directory to the location where your PowerShell script is saved using the `cd` command:
     ```powershell
     cd C:\Temp\MDISetupScripts
     ```

4. **Run the PowerShell Script:**
   - Execute your script using the following command:
     ```powershell
     .\YourScript.ps1
     ```
     Replace "YourScript.ps1" with the actual name of your PowerShell script - etc. '**.\1 - Install the Sensor.ps1**'.


## Scripts Overview:

1. **'1 - Install the Sensor.ps1':**
   - This script installs the MDI sensor on the host. Ensure that the host meet the necessary requirements before running the script and you have the accesskey needed to install the Sensor.

2. **'2 - Create Service Group and Account.ps1':**
   - This script creates a permission group and assigns the gMSA Account account created.

3. **'3 - Create Permission Group and assign gMSAAccount.ps1':**
   - This script is responsible for creating the service group permissions and enable AD Recycle Bin if not setup.

4. **'4 - Validate gMSA Account.ps1':**
   - Run this script to validate the gMSA account on the host. It performs necessary checks and validations to ensure the gMSA account is set up correctly.

5. **'5 - Download and import GPOs.ps1':**
   - This script downloads GPO settings from a specified source and imports them into the current environment. Customize the script with the appropriate source URLs and paths.

## Instructions for Use:

1. **'1 - Install the Sensor.ps1':**
   - Open the script and review the configuration parameters at the beginning of the file.
   - Run the script with the necessary permissions on target host(s) in a PowerShell Console.

2. **'2 - Create Service Group and Account.ps1':**
   - Modify the script parameters to match your environment if needed.
   - Execute the script with the required permissions in a PowerShell Console.

3. **'3 - Create Permission Group and assign gMSAAccount.ps1':**
   - Adjust the script parameters according to your environment if needed.
   - Run the script with the necessary permissions in a PowerShell Console.

4. **'4 - Validate gMSA Account.ps1':**
   - Open the script and update parameters as needed.
   - Execute the script to ensure the gMSA account is set up correctly on the host in a PowerShell Console.

5. **'5 - Download and import GPOs.ps1':**
   - Run the script to download and import GPO settings into your environment if needed.

**Important Notes:**
- Ensure that you have the required permissions to execute these scripts.
- Review and customize the script parameters before running each script.
- Test scripts in a non-production environment before deploying in a live environment.
- Refer to the individual script comments for detailed information on each parameter.