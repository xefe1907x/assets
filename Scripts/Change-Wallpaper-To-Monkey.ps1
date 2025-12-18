
<#
========================= Simple Wallpaper Changer ============================--

SYNOPSIS
This script will download an image from the web and set it as the wallpaper.

USAGE
1. Change DIRECT IMAGE LINK HERE to your URL.
2. Run the script.

#>


$url = "https://media.cnn.com/api/v1/images/stellar/prod/160107100400-monkey-selfie.jpg?q=w_2912,h_1638,x_0,y_0,c_fill"
$outputPath = "$env:temp\img.jpg"
$wallpaperStyle = 2  # 0: Tiled, 1: Centered, 2: Stretched

IWR -Uri $url -OutFile $outputPath

$signature = @'
using System;
using System.Runtime.InteropServices;

public class Wallpaper {
    [DllImport("user32.dll", CharSet = CharSet.Auto)]
    public static extern int SystemParametersInfo(int uAction, int uParam, string lpvParam, int fuWinIni);
}
'@

Add-Type -TypeDefinition $signature

$SPI_SETDESKWALLPAPER = 0x0014
$SPIF_UPDATEINIFILE = 0x01
$SPIF_SENDCHANGE = 0x02

[Wallpaper]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $outputPath, $SPIF_UPDATEINIFILE -bor $SPIF_SENDCHANGE)