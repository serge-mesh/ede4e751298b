import { Link } from "@tanstack/react-router";
import { EmptyState } from "@/components/common/states";
import { Button } from "@/components/ui/button";

export function NotFoundPage() {
  return (
    <EmptyState title="Page not found" action={<Button asChild variant="outline"><Link to="/">Go to the dashboard</Link></Button>}>
      The address doesn't match any page of the Picket UI.
    </EmptyState>
  );
}
