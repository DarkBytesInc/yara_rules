rule Win_Downloader_Agent_35039
{
strings:
	$a0 = { bc8acbbe7b6403f88642279f84e8c6b14742eba0a1be2089d0f2456a8142e7a3aa6c03a9369f2de68e42ccae4be8c619bc6f031c8be428827e1d066289a42a9f9750dc4d7e9d3482955f36b0b398cc5d7e7103b2bc733d823ec76bade27d }

condition:
	$a0
}

        
