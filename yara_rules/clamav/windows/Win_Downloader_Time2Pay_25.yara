rule Win_Downloader_Time2Pay_25
{
strings:
	$a0 = { 571819fea3a5b66476fa877453cf976840f6896453fab3b1cb601a8a46bbed56bf6166c8cbac2532e46d4bf6e5d691144a9bd7af27e81a7e5eddf73ae5ed0e5e685cb08ade1e09c131d1b38c712c39b7cb57b232efcf6c5cce59ecbb375623cb59092e64ff5d298df91e2bcefe735f678d9835b5e54dfed2374b51 }

condition:
	$a0
}

        
