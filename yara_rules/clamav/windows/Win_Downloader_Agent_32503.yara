rule Win_Downloader_Agent_32503
{
strings:
	$a0 = { f8e01451df1adc1d734716a293f686f650e22f5b78274be38e89065e141df6019461260addc26dc6a8c8c0173bb94efa6c27e0ea9f957a83b1cf46004eb619879232125e90672990c23b29f290c600f29cadee5f8a9ecfc84d4d84d1fca82b240bac698ef036ba44f08f23b65ee3f9ebc8d676ddbea5f8f28443027c0067fa97f23a5bcb0830f46ff35476fbe864a923f2e83ff1 }

condition:
	$a0
}

        