# Known problems and restrictions of the code
- During testing an error was discovered that the IPV6 UDP scanning doesn't scan the incoming packets properly. It checks for code 4 type 1 but apparently code 1 type 1 can also mean  unreachable. I don't really have much time I will se wether i can fix it.

- If an interface has only an IPV6 then he won't be listed in the available interfaces list

- The packet creator function don't have a return value determining wether the creation was succesfull. Fortunately other things resolve this problem but it is not perfect.