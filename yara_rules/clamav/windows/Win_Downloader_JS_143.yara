rule Win_Downloader_JS_143
{
strings:
	$a0 = { 2e7662732532322c25323046616c73652530442530412532302532302532302532304d6972636f4c6f6e67642e53656e642530442530412532302532302532302532304d6972636f4c6f6e67313125334425323279742e7662732532322530442530412532302532302532302532307365742532304d6972636f4c6f6e67622532302533442532304d6972636f4c6f6e67632e6372 }

condition:
	$a0
}

        