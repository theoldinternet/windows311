' Simple Calculator
CLS
PRINT "=============================="
PRINT "   QBasic Calculator"
PRINT "=============================="
PRINT
INPUT "Enter first number:  ", a
INPUT "Enter second number: ", b
PRINT
PRINT "Results:"
PRINT "  "; a; " + "; b; " = "; a + b
PRINT "  "; a; " - "; b; " = "; a - b
PRINT "  "; a; " * "; b; " = "; a * b
IF b <> 0 THEN
    PRINT "  "; a; " / "; b; " = "; a / b
ELSE
    PRINT "  Division by zero!"
END IF
IF a >= 0 THEN PRINT "  SQR("; a; ") = "; SQR(a)
