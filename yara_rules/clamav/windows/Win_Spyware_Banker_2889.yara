rule Win_Spyware_Banker_2889
{
strings:
	$a0 = { 4d8d5f4691004ffb3634db671366edf190a865c9cf44fe31fdb49a2f8267b8a321589776162324e4d9ef9e4b20051517f3cdef7b25a6e62e0b55bf71a566635478cb01274550f241764acd89dbc64c043c338054a96bf91b390b981c453b60f809a69a6a510c85473ea504dc17692e7eb5c566900f9986a0f093819accd87fc764f9eea5db22f8da60bcef05b1edb0d29e264265a09b }

condition:
	$a0
}

        