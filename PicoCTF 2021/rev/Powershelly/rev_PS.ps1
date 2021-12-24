#!/usr/bin/pwsh
$input = "./input.txt"

$out = Get-Content -Path $input
$enc = [System.IO.File]::ReadAllBytes("$input")
$encoding = [system.Text.Encoding]::UTF8
$total = 264
$t = 1325
$numLength = 9245
Write-Output $enc.count # has to be == 9245
Write-Output $out.Length # has to be <= 5
if ($out.Length -gt 5 -or $enc.count -ne 9245)
{
  Write-Output "Wrong format 5"
  Exit
}

# input has to be either 1 or 0 or space or new line
else{
  for($i=0; $i -lt $enc.count ; $i++) # loop through letters in input
  {
    if (($enc[$i] -ne 49) -and ($enc[$i] -ne 48) -and ($enc[$i] -ne 10) -and ($enc[$i] -ne 13) -and ($enc[$i] -ne 32))
    {
      Write-Output "Wrong format 1/0/"
      Exit
    }
  }
}

Write-Output "[*] Got to hashtable"
$blocks = @{} # hashtable
# loop through lines
Write-Output "[*] Looping through $($out.length) lines"
for ($i=0; $i -lt $out.Length ; $i++){
  $r = $out[$i].split(" ")
  if ($i -gt 0)  {
    Write-Output "[*] Not first line ??"
    for ($j=0; $j -lt $r.Length ; $j++)    {
      if ($r[$j].Length -ne 6){
        Write-Output "Wrong Format 6" $r[$j].Length
        Exit
      }
      $blocks[$j] += $r[$j]
    }
  }
  else  {
    Write-Output "[*] First line ??"
    # Loop through the lines again
    for ($j=0; $j -lt $r.Length ; $j++)    {
      if ($r[$j].Length -ne 6)    {
        Write-Output "Wrong Format 6" $r[$j].Length
        Exit
      }
      $blocks[$j] = @()
      $blocks[$j] += $r[$j]
    }
  }

}


function Exit  {
  exit
}


function Random-Gen {
  $list1 = @()
  for ($i=1; $i -lt ($blocks.count + 1); $i++)  {
    $y = ((($i * 327) % 681 ) + 344) % 313
    $list1 += $y
  }
  return $list1
}


function Scramble {
    param (
        $block,
        $seed
    )
    $raw = [system.String]::Join("", $block)
    $bm = "10 " * $raw.Length
    $bm = $bm.Split(" ")
    for ($i=0; $i -lt $raw.Length ; $i++){
      $y = ($i * $seed) % $raw.Length
      $n = $bm[$y]
      while ($n -ne "10") {
        $y = ($y + 1) % $raw.Length
        $n = $bm[$y]
      }
      if ($raw[$i] -eq "1" ){
        $n = "11"
      }
      else{
        $n = "00"
      }
      $bm[$y] = $n
    }
    $raw2 = [system.String]::Join("", $bm)
    $b = [convert]::ToInt64($raw2,2)
    return $b
}

Write-Output "[*] Got to Main"
$result = 0
$seeds = @()
for ($i=1; $i -lt ($blocks.count +1); $i++){
  $seeds += ($i * 127) % 500
}

$randoms = Random-Gen
$output_file = @() # empty array

for ($i=0; $i -lt $blocks.count ; $i++){

  $fun = Scramble -block $blocks[$i] -seed $seeds[$i]
  if($i -eq 263)  {
    Write-Output $seeds[$i]
    Write-Output $randoms[$i]
    Write-Output $fun
  }
  $result = $fun -bxor $result -bxor $randoms[$i]
  $output_file += $result
}
Add-Content -Path output.txt -Value $output_file
