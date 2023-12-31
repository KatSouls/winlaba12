#ifndef PIDControl_h;
#define PIDControl_h

class PIDControl
{
public:
#define heaterPin 2
#define sensePin 5
    double currTemp;
    double Output;
    double setTempPoint;
    double setTimePoint;
    int kp;
    int kd;
    int ki;

    PIDControl(double, double, double, unsigned long, int, int, int, int, int, int);
    void optionsPID(int);
    double reflowPID(double, double, unsigned long);
    double setReflowCurve(int, int, int, int, int, int, double, double, unsigned long);
    double setReflowTime(int, int, int, int, int, int, double, double, unsigned long);
    void displayTemp(double, double);

private:
    int _val;
    unsigned long _now;
};

#endif
