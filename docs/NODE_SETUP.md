# Node.js & npm Installation Guide for Windows

This guide provides troubleshooting steps and instructions for setting up Node.js and npm on Windows to run the Aegivion frontend.

## 🔧 Installation Methods

### Method 1: Install via Windows Package Manager (winget)
Open a PowerShell terminal and run:
```powershell
winget install OpenJS.NodeJS
```

### Method 2: Official MSI Installer
1. Download Node.js LTS (Long Term Support) from the official website: https://nodejs.org/
2. Run the `.msi` file and follow the wizard.
3. **Important**: Verify that the option to **"Add to PATH"** is selected.

---

## 🔄 Post-Installation

After installing Node.js, refresh your terminal session:
1. Close your current PowerShell or Command Prompt.
2. Open a new terminal.
3. Verify the installation:
   ```powershell
   node --version
   npm --version
   ```

---

## 📦 Running the Frontend

Once Node.js is verified, launch the development environment:
```powershell
cd packages/frontend
npm install
npm run dev
```
The dashboard will be served at [http://localhost:3000](http://localhost:3000).

## 🛠️ Troubleshooting

### PATH Issues
If `node` is installed but not recognized:
1. Locate your Node installation directory (typically `C:\Program Files\nodejs\`).
2. Add this path to your user or system **Path** variable in the Windows Environment Variables editor (`sysdm.cpl`).
3. Restart your terminal.

### Alternative: Running with Docker
If you prefer not to install Node.js locally:
```powershell
docker-compose up frontend
```
