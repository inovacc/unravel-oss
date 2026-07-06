/**
 * Test Scenario 01: Scientific Calculator
 * Difficulty: Easy (~120 LOC)
 *
 * Tests:
 * - Enum declaration and usage
 * - Switch expressions
 * - Basic arithmetic methods
 * - ArrayList and List usage
 * - String formatting with DecimalFormat
 * - Simple expression parsing
 * - Static methods and main entry point
 *
 * Expected Go mappings:
 * - enum Operation       -> const iota block
 * - List<String>         -> []string
 * - DecimalFormat        -> fmt.Sprintf or strconv.FormatFloat
 * - switch expression    -> switch statement
 * - Math.pow/Math.sqrt   -> math.Pow/math.Sqrt
 * - System.out.println   -> fmt.Println
 */

import java.util.ArrayList;
import java.util.List;
import java.text.DecimalFormat;

public class Calculator {

    public enum Operation {
        ADD,
        SUBTRACT,
        MULTIPLY,
        DIVIDE,
        POWER,
        SQRT
    }

    private final List<String> history;
    private final DecimalFormat formatter;

    public Calculator() {
        this.history = new ArrayList<>();
        this.formatter = new DecimalFormat("#,##0.######");
    }

    public double calculate(Operation op, double a, double b) {
        double result = switch (op) {
            case ADD -> a + b;
            case SUBTRACT -> a - b;
            case MULTIPLY -> a * b;
            case DIVIDE -> {
                if (b == 0) {
                    throw new ArithmeticException("Division by zero");
                }
                yield a / b;
            }
            case POWER -> Math.pow(a, b);
            case SQRT -> {
                if (a < 0) {
                    throw new ArithmeticException("Square root of negative number");
                }
                yield Math.sqrt(a);
            }
        };

        String entry = formatEntry(op, a, b, result);
        history.add(entry);
        return result;
    }

    private String formatEntry(Operation op, double a, double b, double result) {
        return switch (op) {
            case ADD -> String.format("%s + %s = %s", format(a), format(b), format(result));
            case SUBTRACT -> String.format("%s - %s = %s", format(a), format(b), format(result));
            case MULTIPLY -> String.format("%s * %s = %s", format(a), format(b), format(result));
            case DIVIDE -> String.format("%s / %s = %s", format(a), format(b), format(result));
            case POWER -> String.format("%s ^ %s = %s", format(a), format(b), format(result));
            case SQRT -> String.format("sqrt(%s) = %s", format(a), format(result));
        };
    }

    public String formatResult(double value) {
        if (Double.isNaN(value)) {
            return "NaN";
        }
        if (Double.isInfinite(value)) {
            return value > 0 ? "Infinity" : "-Infinity";
        }
        return formatter.format(value);
    }

    private String format(double value) {
        return formatResult(value);
    }

    public double parseAndCalculate(String expression) {
        expression = expression.trim();

        for (String operator : new String[]{"+", "-", "*", "/", "^"}) {
            int idx = expression.lastIndexOf(operator);
            if (idx > 0) {
                double left = Double.parseDouble(expression.substring(0, idx).trim());
                double right = Double.parseDouble(expression.substring(idx + 1).trim());
                Operation op = switch (operator) {
                    case "+" -> Operation.ADD;
                    case "-" -> Operation.SUBTRACT;
                    case "*" -> Operation.MULTIPLY;
                    case "/" -> Operation.DIVIDE;
                    case "^" -> Operation.POWER;
                    default -> throw new IllegalArgumentException("Unknown operator: " + operator);
                };
                return calculate(op, left, right);
            }
        }

        if (expression.startsWith("sqrt(") && expression.endsWith(")")) {
            double operand = Double.parseDouble(expression.substring(5, expression.length() - 1).trim());
            return calculate(Operation.SQRT, operand, 0);
        }

        return Double.parseDouble(expression);
    }

    public List<String> getHistory() {
        return List.copyOf(history);
    }

    public void clearHistory() {
        history.clear();
    }

    public int getHistorySize() {
        return history.size();
    }

    public static void main(String[] args) {
        Calculator calc = new Calculator();

        System.out.println("=== Scientific Calculator ===");
        System.out.println();

        double sum = calc.calculate(Operation.ADD, 10.5, 20.3);
        System.out.println("10.5 + 20.3 = " + calc.formatResult(sum));

        double quotient = calc.calculate(Operation.DIVIDE, 100, 7);
        System.out.println("100 / 7 = " + calc.formatResult(quotient));

        double power = calc.calculate(Operation.POWER, 2, 10);
        System.out.println("2 ^ 10 = " + calc.formatResult(power));

        double sqrt = calc.calculate(Operation.SQRT, 144, 0);
        System.out.println("sqrt(144) = " + calc.formatResult(sqrt));

        double parsed = calc.parseAndCalculate("25 + 17");
        System.out.println("Parsed '25 + 17' = " + calc.formatResult(parsed));

        System.out.println();
        System.out.println("=== History (" + calc.getHistorySize() + " entries) ===");
        for (String entry : calc.getHistory()) {
            System.out.println("  " + entry);
        }
    }
}
