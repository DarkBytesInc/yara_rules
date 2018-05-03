rule Win_Tool_Kerbsniff_1
{
strings:
	$a0 = { 6b657262736e696666203c63617074757265206f75747075742066696c65206e616d653e }

condition:
	$a0
}

        
