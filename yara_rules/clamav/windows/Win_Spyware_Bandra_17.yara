rule Win_Spyware_Bandra_17
{
strings:
	$a0 = { 38812710012b7a393b30745a5f57505e2e2e01c00a03276741736d78184f686c7d9a8011568338120b4d656d7911c5e0c3fa9140e8c4e084fdf3a9949a9c9a5e58000687f0f17010930c923040b0e4abbab9b8aedf1880619b5911a067c8125fcf88b0c184012038b3e1dac6d7b153ac2c013430abe1c0cb85b5e59f82 }

condition:
	$a0
}

        