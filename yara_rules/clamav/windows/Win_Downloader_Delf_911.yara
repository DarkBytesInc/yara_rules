rule Win_Downloader_Delf_911
{
strings:
	$a0 = { 2f5dc20ab57e2864151a0dc6df584e4ea75d56ffd4c43eae85f37c92a3c5d7e3b9551dd9089bd7e73ff9aecd60cfae1c2e337f8e5b8e741bb843517de2dd1e721f82149cfc55e7b9d9055ae3b44ca3e208af70ddbfef87fa0f4dc5b7e6c8d398b138c7a8 }

condition:
	$a0
}

        
