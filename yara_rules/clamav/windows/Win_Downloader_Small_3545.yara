rule Win_Downloader_Small_3545
{
strings:
	$a0 = { a96d595ac14d6c595ac15b5959d941625d5959e496b969595adc1d6de6ed7d6d5a5959ab0c5aafe1f7816359595830c15d5a5959e69d7d6da9c13d6c595ac17d6d595ac15b5959d941285c5959e6a57d7daa419e585858e486b569595adc1d }

condition:
	$a0
}

        