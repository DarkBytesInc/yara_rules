rule Win_Trojan_Robobot_84
{
strings:
	$a0 = { 61f76c5bf5354de8a1b057294b2ce1a8b1e8e703b3117c25a7bcd85f1cfff3eaca5c4f0e62e64fd0431d1b69991db08035555ce560777ba7fef874b888bf70c027777b20062a8278edc2e084a6f030e8251ae9f6602fa2f902ea1f659d4627ec1cacca5955fffb40ce58c555bb8b130b092fa5acc15ce02ac86e57de6f70964441c3fad88ffaf56c8ba85876ee4bb5f2eeb06b31e9a6 }

condition:
	$a0
}

        