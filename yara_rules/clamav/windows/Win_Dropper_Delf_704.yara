rule Win_Dropper_Delf_704
{
strings:
	$a0 = { be68953478813278856dbe689117347897f6386dbebebe29bdbdbd30386dbebebe6dbe688d32381dbebebe3a95bb08513ac069bebebeb8085a3ac065bebebebc0bb117327897bafd1734789792af17327897bafd173afdbb173478976b6c6a3260811932b8a5bdbdbd327d4d327db13afdb132b544fc095934f37f3a03b5bd7f32b4098d7f4263a50893173270971734735917347357 }

condition:
	$a0
}

        