rule Win_Downloader_Small_4868
{
strings:
	$a0 = { 444f574e8c116c0245584543555411776e596811c1fd26707606cb732f7760d29a692e629a1d8b6476d14f73dc66e591dd63636d7f12ddd22d64190d32afe32e62e533992d73721cdeeb4584af104e1d23d27f96bf22cd7f64e71a1afd618cd77981bd629d41444c4ceb5900e0005f5f76626146726565566172b86de1724475704f7368 }

condition:
	$a0
}

        