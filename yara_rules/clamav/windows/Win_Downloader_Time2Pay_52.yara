rule Win_Downloader_Time2Pay_52
{
strings:
	$a0 = { ce3b1cfe3a86b364efd98274caec9268d9d58c64cad9b6b152431f8adf98e856264263c8528f20327d4e4ef67cf59414d3b8d2cfbecb1f7ec7fef23a7cce0b5ef17fb58a473d0cc1a8f2b68ce80f3cb75274b73276ec695c577ae99bae7546cbc02a2b64661e2c6d60dd2ece07505a6714bb30957c6efbd2ae6874 }

condition:
	$a0
}

        
