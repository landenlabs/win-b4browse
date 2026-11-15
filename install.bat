
@rem Use an existing binDir if it's set and points at a real directory; otherwise default.
if not defined binDir set binDir=c:\opt\bin
if not exist "%binDir%\" set binDir=c:\opt\bin


@rem dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true
dotnet publish -c Release -r win-x64 --self-contained true /p:PublishSingleFile=true /p:EnableCompressionInSingleFile=true

copy .\bin\Release\net10.0-windows\win-x64\publish\B4Browse.exe "%binDir%"
 
