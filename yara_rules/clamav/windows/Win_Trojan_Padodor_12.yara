rule Win_Trojan_Padodor_12
{
strings:
	$a0 = { 2cce078dc4a826db2c2f42d7a5658413d3e487e72da47222a5676ddba1f1fb897f5b72d77a4c68fa2ca46ddba1e1fb8b46a66f18c2e6078dc4f826db2c2dff2ccb2d4223a7e1ff52ebf2ef5933a4078472ffce18792de26390a405dbc4e419db2cf7518c975c2639412ddf }

condition:
	$a0
}

        
