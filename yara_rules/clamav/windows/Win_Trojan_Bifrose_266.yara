rule Win_Trojan_Bifrose_266
{
strings:
	$a0 = { ed52b2fda1f1ef9162a1145e683de4d46d7ed4ca892a80246d26c055ce28129c8497d26044470aaf98311357e830aa6371e6ff36e7f5106578eba3575b8417774c23d740682627d4b923e8221b150134c2f613e37eb4ff2cadc6d2c8944794edf5231f4d1bc15028788b044c97d2b6cceddb9b6dd3afa9c0449b0a9699290b3fcbc39f7fda1dbf56e3a2835d }

condition:
	$a0
}

        