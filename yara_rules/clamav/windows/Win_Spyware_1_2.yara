rule Win_Spyware_1_2
{
strings:
	$a0 = { 61bb2728fd5556cae5306f6e285e16ed4f28c5218c98e84668d696b819ca6e1467b4546097b8c070a456849f08e5ebadbb714e3f2fb08d899079c757ce3a97cb2ccc8aea5c2b261108f4d0b87986047a4df35c45491c429a19a0f29bbf4522f81a4842367098e35629fe33e51f7bdd15cf108c1a5689a8f9b804ee20300626409f52319943e755b26ca6b4d870436cf6793008 }

condition:
	$a0
}

        