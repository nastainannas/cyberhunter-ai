#!/bin/bash
# Assemble CYBERHUNTER AI demo video from captured assets.
FF="/c/Users/ADMPROD-05-PC/AppData/Local/Microsoft/WinGet/Packages/Gyan.FFmpeg_Microsoft.Winget.Source_8wekyb3d8bbwe/ffmpeg-9.0.2-full_build/bin/ffmpeg.exe"
VID="/c/Users/ADMPROD-05-PC/Documents/project/hack/submission-assets/video"
OUT="/c/Users/ADMPROD-05-PC/Documents/project/hack/submission-assets/cyberhunter-demo.mp4"
FONT="font.ttf"
cd "$VID"
mkdir -p "$VID/seg"
rm -f "$VID/seg"/*.mp4 "$VID"/concat.txt

still() { # $1=image $2=seconds $3=outfile [$4=label]
  local vf="scale=1280:720:force_original_aspect_ratio=decrease,pad=1280:720:(ow-iw)/2:(oh-ih)/2:color=0x0A0E13,fps=30"
  if [ -n "$4" ]; then
    vf="$vf,drawtext=fontfile=$FONT:text='$4':fontsize=34:fontcolor=white:x=40:y=h-70:box=1:boxcolor=black@0.45:boxborderw=14"
  fi
  vf="$vf,fade=t=in:st=0:d=0.4,fade=t=out:st=$(awk "BEGIN{print $2-0.5}"):d=0.5"
  "$FF" -y -loop 1 -t "$2" -i "$1" -vf "$vf" -pix_fmt yuv420p -r 30 -c:v libx264 -preset fast -crf 21 "$3" 2>/dev/null
}

# 1. title card
"$FF" -y -f lavfi -i "color=c=0x0A0E13:s=1280x720:d=4" \
  -vf "drawtext=fontfile=$FONT:text='CYBERHUNTER AI':fontsize=72:fontcolor=white:x=(w-text_w)/2:y=270,drawtext=fontfile=$FONT:text='AI-Powered Automated Vulnerability Assessment':fontsize=30:fontcolor=0x60A5FA:x=(w-text_w)/2:y=380,drawtext=fontfile=$FONT:text='Oleh Nastain - Team Ternakheck':fontsize=24:fontcolor=0x94A3B8:x=(w-text_w)/2:y=450" \
  -pix_fmt yuv420p -r 30 -c:v libx264 -preset fast -crf 21 "$VID/seg/00-title.mp4" 2>/dev/null

# 2. slides (4s each)
i=1
for f in "$VID"/slides/s*.png; do
  n=$(basename "$f" .png)
  still "$f" 4 "$VID/seg/${n}.mp4"
  i=$((i+1))
done

# 3. app pages (5s each, labeled)
declare -A LAB=( [dashboard]="Dashboard" [scan]="Scan Target - Live Log" [findings]="Findings Database" [ai-config]="AI Configuration" [tools]="Tools" )
for name in dashboard scan findings ai-config tools; do
  still "$VID/app/${name}.png" 5 "$VID/seg/app-${name}.mp4" "${LAB[$name]}"
done

# 4. live scan frames -> ~30s at 2fps
"$FF" -y -framerate 2 -i "$VID/live/f%03d.png" -vf "scale=1280:720:force_original_aspect_ratio=decrease,pad=1280:720:(ow-iw)/2:(oh-ih)/2:color=0x0A0E13,fps=30,drawtext=fontfile=$FONT:text='LIVE SCAN - localhost:5173':fontsize=30:fontcolor=0x60A5FA:x=40:y=40:box=1:boxcolor=black@0.5:boxborderw=12" -pix_fmt yuv420p -c:v libx264 -preset fast -crf 21 "$VID/seg/live-scan.mp4" 2>/dev/null

# 5. closing card
"$FF" -y -f lavfi -i "color=c=0x0A0E13:s=1280x720:d=4" \
  -vf "drawtext=fontfile=$FONT:text='Terima Kasih':fontsize=64:fontcolor=white:x=(w-text_w)/2:y=300,drawtext=fontfile=$FONT:text='github.com/nastainannas/cyberhunter-ai':fontsize=28:fontcolor=0x3B82F6:x=(w-text_w)/2:y=390" \
  -pix_fmt yuv420p -r 30 -c:v libx264 -preset fast -crf 21 "$VID/seg/99-end.mp4" 2>/dev/null

# concat in order
ls "$VID"/seg/00-title.mp4 "$VID"/seg/s*.mp4 "$VID"/seg/app-*.mp4 "$VID"/seg/live-scan.mp4 "$VID"/seg/99-end.mp4 | sed "s|^|file '|;s|$|'|" > "$VID/concat.txt"
"$FF" -y -f concat -safe 0 -i "$VID/concat.txt" -c copy "$OUT" 2>/dev/null

"$FF" -i "$OUT" 2>&1 | grep Duration
ls -la "$OUT"
