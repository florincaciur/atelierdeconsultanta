#requires -Version 7.2
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $InputDirectory,
    [Parameter(Mandatory)] [string] $OutputDirectory,
    [Parameter(Mandatory)] [string] $ModelPath,
    [string] $FFmpeg = 'ffmpeg.exe',
    [string] $Whisper = 'whisper-cli.exe',
    [ValidateRange(1, 3)] [int] $Limit = 3
)

$ErrorActionPreference = 'Stop'

function Invoke-VideoTool {
    param([string] $Executable, [string[]] $ToolArguments)
    & $Executable @ToolArguments
    if ($LASTEXITCODE -ne 0) {
        throw "Procesul $Executable a esuat cu codul $LASTEXITCODE."
    }
}

$ffmpegPath = (Get-Command -Name $FFmpeg -CommandType Application).Source
$whisperPath = (Get-Command -Name $Whisper -CommandType Application).Source
$model = Get-Item -LiteralPath $ModelPath
if ($model.PSIsContainer -or $model.Length -eq 0) { throw 'Alege fisierul modelului Whisper.' }
$sourceDirectory = (Resolve-Path -LiteralPath $InputDirectory).ProviderPath
$destinationDirectory = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
if ([string]::Equals([IO.Path]::TrimEndingDirectorySeparator($sourceDirectory), [IO.Path]::TrimEndingDirectorySeparator($destinationDirectory), [StringComparison]::OrdinalIgnoreCase)) {
    throw 'Alege dosare diferite pentru filmari si exporturi.'
}

$clips = Get-ChildItem -LiteralPath $sourceDirectory -File |
    Where-Object Extension -In '.mp4', '.mov', '.m4v', '.mkv' |
    Sort-Object Name
$duplicateNames = $clips | Group-Object BaseName | Where-Object Count -gt 1
if ($duplicateNames) { throw "Redenumeste filmarile cu acelasi nume de baza: $($duplicateNames.Name -join ', ')." }
$pending = $clips | Where-Object {
    -not (Test-Path -LiteralPath (Join-Path $destinationDirectory "$($_.BaseName).mp4"))
} | Select-Object -First $Limit
if (!$pending) { Write-Host 'Nu sunt filmari noi de exportat.'; return }

[IO.Directory]::CreateDirectory($destinationDirectory) | Out-Null
$vertical = 'scale=1080:1920:force_original_aspect_ratio=increase,crop=1080:1920,setsar=1,fps=30'
$captions = "subtitles=clip.srt:charenc=UTF-8:force_style='FontName=Arial,FontSize=16,Outline=2,Shadow=0,MarginV=32,MarginL=24,MarginR=24'"

foreach ($clip in $pending) {
    Write-Host "Procesez $($clip.Name)"
    $tempDirectory = Join-Path $destinationDirectory ('.edit-' + [guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($tempDirectory) | Out-Null
    Push-Location -LiteralPath $tempDirectory
    try {
        $reviewedCaptions = Join-Path $sourceDirectory "$($clip.BaseName).srt"
        if (Test-Path -LiteralPath $reviewedCaptions -PathType Leaf) {
            Copy-Item -LiteralPath $reviewedCaptions -Destination 'clip.srt'
        } else {
            Invoke-VideoTool $ffmpegPath @('-nostdin', '-hide_banner', '-loglevel', 'error', '-i', $clip.FullName, '-map', '0:a:0', '-ar', '16000', '-ac', '1', '-c:a', 'pcm_s16le', 'speech.wav')
            Invoke-VideoTool $whisperPath @('-m', $model.FullName, '-f', 'speech.wav', '-l', 'ro', '-osrt', '-of', 'clip', '-ml', '38', '-sow', '-np')
        }
        if (!(Test-Path -LiteralPath 'clip.srt' -PathType Leaf) -or (Get-Item -LiteralPath 'clip.srt').Length -eq 0) {
            throw "Subtitrarile lipsesc pentru $($clip.Name). Verifica inregistrarea audio."
        }

        Invoke-VideoTool $ffmpegPath @(
            '-nostdin', '-hide_banner', '-loglevel', 'error', '-i', $clip.FullName,
            '-map', '0:v:0', '-map', '0:a:0', '-map_metadata', '-1', '-map_chapters', '-1',
            '-vf', "$vertical,$captions", '-af', 'loudnorm=I=-16:TP=-1.5:LRA=11', '-ar', '48000',
            '-c:v', 'libx264', '-preset', 'fast', '-crf', '21', '-pix_fmt', 'yuv420p',
            '-c:a', 'aac', '-b:a', '128k', '-movflags', '+faststart', 'export.mp4'
        )
        $subtitlePath = Join-Path $destinationDirectory "$($clip.BaseName).srt"
        $videoPath = Join-Path $destinationDirectory "$($clip.BaseName).mp4"
        [IO.File]::Copy((Join-Path $tempDirectory 'clip.srt'), $subtitlePath, $true)
        [IO.File]::Move((Join-Path $tempDirectory 'export.mp4'), $videoPath)
        Write-Host "Exportat $videoPath"
    } finally {
        Pop-Location
        foreach ($name in 'speech.wav', 'clip.srt', 'export.mp4') {
            [IO.File]::Delete((Join-Path $tempDirectory $name))
        }
        [IO.Directory]::Delete($tempDirectory)
    }
}
