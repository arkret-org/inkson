function mountMessageMenu(menuId) {
  const menu = document.getElementById(menuId);
  const message = menu?.closest('.discussion-message');
  const trigger = message?.querySelector('.chat-message-menu-button');
  const feed = message?.closest('[data-testid="message-list"]');
  if (!menu || !trigger || !feed) return;

  // The top layer escapes clipping and stacking contexts in embedded chats.
  message.querySelector('.message-context-menu-scrim')?.showPopover();
  menu.showPopover();
  const gap = 6;
  const gutter = 8;
  let frame = 0;
  const viewport = window.visualViewport;
  const position = () => {
    frame = 0;
    if (!menu.isConnected || !trigger.isConnected) return;
    const bounds = feed.getBoundingClientRect();
    const anchor = trigger.getBoundingClientRect();
    const left = Math.max(bounds.left, viewport?.offsetLeft ?? 0) + gutter;
    const top = Math.max(bounds.top, viewport?.offsetTop ?? 0) + gutter;
    const right = Math.min(bounds.right,
      (viewport?.offsetLeft ?? 0) + (viewport?.width ?? window.innerWidth)) - gutter;
    const bottom = Math.min(bounds.bottom,
      (viewport?.offsetTop ?? 0) + (viewport?.height ?? window.innerHeight)) - gutter;
    if (right <= left || bottom <= top || anchor.bottom <= top || anchor.top >= bottom) {
      message.querySelector('.message-context-menu-scrim')?.click();
      return;
    }

    menu.style.minWidth = `${Math.min(176, right - left)}px`;
    menu.style.maxWidth = `${Math.min(240, right - left)}px`;
    // Measure natural height before deciding which side has enough space.
    const scrollTop = menu.scrollTop;
    menu.style.maxHeight = 'none';
    const height = menu.getBoundingClientRect().height;
    const below = Math.max(0, bottom - anchor.bottom - gap);
    const above = Math.max(0, anchor.top - top - gap);
    const opensAbove = height > below && above > below;
    const available = opensAbove ? above : below;
    menu.style.maxHeight = `${available}px`;
    const size = menu.getBoundingClientRect();
    menu.style.left = `${Math.max(left, Math.min(anchor.right - size.width, right - size.width))}px`;
    menu.style.top = `${opensAbove ? anchor.top - gap - size.height : anchor.bottom + gap}px`;
    menu.scrollTop = scrollTop;
    menu.style.visibility = 'visible';
  };
  const schedule = () => {
    if (!frame) frame = requestAnimationFrame(position);
  };
  const onKeyDown = (event) => {
    if (event.key === 'Escape') {
      event.preventDefault();
      requestAnimationFrame(() => {
        if (trigger.isConnected) trigger.focus({ preventScroll: true });
      });
      return; // Dioxus closes the menu and keeps its controller state in sync.
    }
    const items = [...menu.querySelectorAll('[role="menuitem"]:not(:disabled)')];
    if (!items.length) return;
    const index = items.indexOf(document.activeElement);
    let next;
    if (event.key === 'ArrowDown') next = (index + 1) % items.length;
    if (event.key === 'ArrowUp') next = (index - 1 + items.length) % items.length;
    if (event.key === 'Home') next = 0;
    if (event.key === 'End') next = items.length - 1;
    if (next === undefined) return;
    event.preventDefault();
    items[next].focus({ preventScroll: true });
    // Scroll this panel alone; scrollIntoView would also move the chat feed.
    const item = items[next].getBoundingClientRect();
    const panel = menu.getBoundingClientRect();
    if (item.bottom > panel.bottom) menu.scrollTop += item.bottom - panel.bottom + 4;
    if (item.top < panel.top) menu.scrollTop -= panel.top - item.top + 4;
  };
  const resize = new ResizeObserver(schedule);
  resize.observe(feed);
  resize.observe(message);
  resize.observe(menu);
  document.addEventListener('scroll', schedule, true);
  window.addEventListener('resize', schedule);
  viewport?.addEventListener('resize', schedule);
  viewport?.addEventListener('scroll', schedule);
  menu.addEventListener('keydown', onKeyDown);
  const removed = new MutationObserver(() => {
    if (menu.isConnected && trigger.isConnected) return;
    cancelAnimationFrame(frame);
    cancelAnimationFrame(focusFrame);
    resize.disconnect();
    removed.disconnect();
    document.removeEventListener('scroll', schedule, true);
    window.removeEventListener('resize', schedule);
    viewport?.removeEventListener('resize', schedule);
    viewport?.removeEventListener('scroll', schedule);
    menu.removeEventListener('keydown', onKeyDown);
  });
  removed.observe(document.body, { childList: true, subtree: true });
  position();
  // Wait for popover activation and the triggering key's default action.
  const focusFrame = requestAnimationFrame(() => {
    menu.querySelector('[role="menuitem"]:not(:disabled)')?.focus({ preventScroll: true });
  });
}
