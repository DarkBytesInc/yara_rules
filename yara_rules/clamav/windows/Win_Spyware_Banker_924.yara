rule Win_Spyware_Banker_924
{
strings:
	$a0 = { c3aa5a251bd6b848f99e8eecd37dc3f1cd9371badef4e160cffeffaffa973650ad2b8ec5e4da54c54d33d0c8d9151ea51f1fa12f958dffffff8b0cc8a6df4d48a99bae50030a4a8127c448700101ca6a0edc1e5ed2ffffffff8cca166e13b21eb97de6e973de3b4baf39bfb49667426fba13a37eb27df6c9dfd6ffffff10d5cf17e9897795c81b7b90e6c21336aa055a3fbbcff57f44 }

condition:
	$a0
}

        