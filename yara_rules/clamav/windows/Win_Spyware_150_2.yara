rule Win_Spyware_150_2
{
strings:
	$a0 = { c1b0b71cb316b1a932f6424203ddc6a5285af9fd8af946276deaaa5415d80196b3c15cc115dff5c0721944261d5208fc4238bad23f70fa76e203776f99a2917f7b6c9914d209e2ad2837276472ec473bb4382084c7485f090632e891dfbf }

condition:
	$a0
}

        