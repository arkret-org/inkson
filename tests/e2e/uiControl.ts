import type { Locator, Page } from "@playwright/test";
import { byClass } from "./strandsHarness";

/** A real editable control can be the widget root or its associated field child. */
export function inputByClass(root: Page | Locator, className: string): Locator {
  return byClass(root, className).locator(
    "xpath=self::input | self::textarea | self::*[@contenteditable='true' or @contenteditable='plaintext-only'] | .//input | .//textarea | .//*[@contenteditable='true' or @contenteditable='plaintext-only']",
  );
}
