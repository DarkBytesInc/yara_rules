rule Win_Downloader_Delf_433
{
strings:
	$a0 = { 129a7a6406716170112480eaa6c74054d76155c55f70db8813e9b4acf8d66cc6d49a079accc15523c3844851b5ea6de31bbf8956cbc7d73f0749ee7afbade0318b63137e5c35d07b5ff7b2186186778513fd85383ef31a87d9e3ea38025c0a9d9101def8fc1cbb293c02b6414df466db5f4a89256638f01a785a87d75fe1ac7ae42771b65b932473437adf94812edbf9d5bd20ee2af6 }

condition:
	$a0
}

        