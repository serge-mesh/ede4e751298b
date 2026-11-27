// The availability registry (api/availability.ts) is empty while core serves everything the UI
// uses; tests of the "not available yet" mechanism register endpoints and series for themselves.
import { afterEach } from "vitest";
import { NOT_BUILT_ENDPOINTS, NOT_BUILT_SERIES } from "@/api/availability";

const saved = { endpoints: [...NOT_BUILT_ENDPOINTS], series: [...NOT_BUILT_SERIES] };

/** Registers `endpoints` and `series` as not built until the test ends. */
export function registerNotBuilt({ endpoints = [], series = [] }: { endpoints?: string[]; series?: string[] }) {
  NOT_BUILT_ENDPOINTS.push(...endpoints.map((path) => ({ path, spec: "test" })));
  NOT_BUILT_SERIES.push(...series);
}

afterEach(() => {
  NOT_BUILT_ENDPOINTS.splice(0, NOT_BUILT_ENDPOINTS.length, ...saved.endpoints);
  NOT_BUILT_SERIES.splice(0, NOT_BUILT_SERIES.length, ...saved.series);
});
