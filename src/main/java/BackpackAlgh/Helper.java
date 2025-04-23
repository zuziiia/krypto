package BackpackAlgh;

import java.math.BigInteger;
import java.util.List;

public class Helper {

    public static boolean isSuperIncreasing(List<BigInteger> sequence){
        BigInteger sum = BigInteger.ZERO;
        for (BigInteger value : sequence) {
            if (value.compareTo(sum) <= 0) {
                return false;
            }
            sum = sum.add(value);
        }
        return true;

    }
}
