// FIXTURE: React 17+ new JSX transform output. Distinguishing markers:
//   - _jsx( / _jsxs( factories (HIGH confidence)
//   - useState hook reference
//   - __SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED unique marker
import { _jsx, _jsxs } from "react/jsx-runtime";
const __secret = __SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED;
function App() {
  const [count, setCount] = useState(0);
  return _jsxs("div", { children: [_jsx("h1", { children: "hi" }), _jsx("p", { children: count })] });
}
// version literal: 'react@18.2.0'
