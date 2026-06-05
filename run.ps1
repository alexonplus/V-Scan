Start-Process powershell -ArgumentList "-NoExit", "-Command", "dotnet run --project Protector.API --launch-profile http"
Start-Sleep 2
Set-Location protector-web
npm run dev
