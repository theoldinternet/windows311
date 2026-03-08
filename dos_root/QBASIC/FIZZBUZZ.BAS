' FizzBuzz - Classic Programming Challenge
CLS
PRINT "FizzBuzz from 1 to 30:"
PRINT "----------------------"
FOR i = 1 TO 30
    IF i MOD 15 = 0 THEN
        PRINT "FizzBuzz"
    ELSEIF i MOD 3 = 0 THEN
        PRINT "Fizz"
    ELSEIF i MOD 5 = 0 THEN
        PRINT "Buzz"
    ELSE
        PRINT i
    END IF
NEXT i
PRINT "Done!"
