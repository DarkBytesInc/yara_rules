rule Win_Downloader_Wintrim_33
{
strings:
	$a0 = { 615172ffeffe829e37312c300139007b44374138324131322db6ffffff303546352d343244382d423330442d36454639393530373544127dfd14b406df74aca34d414ab6c1d6f40777ff72ff2e10650bfd7f8a1d730c5f494e5452 }

condition:
	$a0
}

        