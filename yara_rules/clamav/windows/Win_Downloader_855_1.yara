rule Win_Downloader_855_1
{
strings:
	$a0 = { 96bb143c94c1c9a1530288c8ed7485f6ce77fcad37e996d60cbbfc130bec0cdc9189e2addffc7e1e065dd5e982f45a80ea66db9e3be178c219a7d2097dd647b6b66b9b2e1b7ce12cb1c82e3adbd9c9818426f410871c731ba5b77bc9ec0cc25a2771b2b599747b79bf5508f0090cc0b0cdbf59021a35c94be27683fc }

condition:
	$a0
}

        