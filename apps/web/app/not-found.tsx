import { ErrorView } from "../src/ui/errors";

// the same page for a missing and for a hidden case file (ADR-9)
export default function NotFound() {
  return <ErrorView status={404} />;
}
