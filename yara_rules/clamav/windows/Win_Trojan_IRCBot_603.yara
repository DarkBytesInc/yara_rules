rule Win_Trojan_IRCBot_603
{
strings:
	$a0 = { 4267ad2b5e0a58cfe1029d7d22272db20b20992b6da39f1020bd2b269d6e35983124e96bc50a3e4c8dc0e9e424a0157bfcf22844bfe4bd78112d82268dee63a60f5e0d69e45adc874df5f73868fad9974f284a9a36375c38e6e639bb43f329736b3277cc3cf95e38bd0629d7c4a172161b8d039e5b396d2f1b78919b19c46f3aee311b4777a04d074b32cce42949fc2e62d063c2f57a }

condition:
	$a0
}

        