import { QueryClient } from "@tanstack/react-query";
import { ApiError } from "@/api/errors";

export function makeQueryClient(opts: { retry?: boolean } = {}) {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 15_000,
        refetchOnWindowFocus: true,
        retry:
          opts.retry === false
            ? false
            : (count, e) => {
                // Client errors won't change on retry; network blips and 5xx get two more tries.
                if (e instanceof ApiError && e.status >= 400 && e.status < 500) return false;
                return count < 2;
              },
      },
      mutations: { retry: false },
    },
  });
}
