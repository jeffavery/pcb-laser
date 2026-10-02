"""Deterministic small-board compiler used after AI produces a circuit netlist."""
from __future__ import annotations

import heapq
import html
import math
import random
import time

PIN_COUNTS = {
    "resistor": 2, "capacitor": 2, "led": 2, "diode": 2,
    "transistor": 3, "ic8": 8, "ic14": 14, "ic16": 16,
    "connector2": 2, "switch2": 2,
}

MAX_BOARD_WIDTH = 100
MAX_BOARD_HEIGHT = 80


def board_dimensions(component_count, enclosure=False, columns=6):
    row_height = 19
    rows = math.ceil(component_count / columns)
    width = 98
    height = max(70 if rows > 1 else 55, 8 + rows * row_height + 8)
    holes = ([(4.5, 4.5), (width - 4.5, 4.5),
              (4.5, height - 4.5), (width - 4.5, height - 4.5)]
             if enclosure else [])
    return {"width": width, "height": height, "hole_diameter": 3.2, "holes": holes,
            "horizontal_spacing": width - 9, "vertical_spacing": height - 9}


def _pad_positions(kind, origin, smd):
    x, y = origin
    count = PIN_COUNTS[kind]
    if kind.startswith("ic"):
        half = count // 2
        pitch = 1.27 if smd else 2.54
        span = 5.4 if smd else 7.62
        left = [(x, y + i * pitch) for i in range(half)]
        right = [(x + span, y + (half - 1 - i) * pitch) for i in range(half)]
        return left + right
    if count == 3:
        if smd:  # SOT-23: two pads on one side, one centered opposite.
            return [(x, y), (x + 1.9, y), (x + .95, y + 2.0)]
        return [(x, y), (x + 2.54, y), (x + 5.08, y)]
    if smd:
        spans = {"resistor": 2.0, "capacitor": 2.0, "led": 2.0,
                 "diode": 3.6, "connector2": 3.5, "switch2": 4.0}
    else:
        spans = {"resistor": 7.62, "capacitor": 5.0, "led": 2.54,
                 "diode": 7.62, "connector2": 5.08, "switch2": 5.08}
    return [(x, y), (x + spans[kind], y)]


def _smd_pad_size(kind):
    if kind.startswith("ic"):
        return 1.5, .65
    return {
        "resistor": (1.2, 1.4), "capacitor": (1.2, 1.4), "led": (1.2, 1.4),
        "diode": (1.7, 1.8), "transistor": (1.0, 1.2),
        "connector2": (2.2, 2.2), "switch2": (2.2, 2.2),
    }[kind]


def _route(start, goals, blocked, width, height, step=.5):
    def cell(point): return (round(point[0] / step), round(point[1] / step))
    def point(c): return (c[0] * step, c[1] * step)
    start_cell = cell(start)
    goal_cells = {cell(g) for g in goals}
    queue = [(0, 0, start_cell)]
    came = {start_cell: None}
    cost = {start_cell: 0}
    serial = 0
    max_x, max_y = round(width / step), round(height / step)
    reached = None
    while queue:
        _score, _serial, current = heapq.heappop(queue)
        if current in goal_cells:
            reached = current
            break
        for dx, dy in ((1, 0), (-1, 0), (0, 1), (0, -1)):
            nxt = (current[0] + dx, current[1] + dy)
            if not (4 <= nxt[0] <= max_x - 4 and 4 <= nxt[1] <= max_y - 4):
                continue
            if nxt in blocked and nxt not in goal_cells and nxt != start_cell:
                continue
            new_cost = cost[current] + 1
            if new_cost >= cost.get(nxt, 10**9):
                continue
            cost[nxt] = new_cost
            came[nxt] = current
            serial += 1
            distance = min(abs(nxt[0] - g[0]) + abs(nxt[1] - g[1]) for g in goal_cells)
            heapq.heappush(queue, (new_cost + distance, serial, nxt))
    if reached is None:
        raise ValueError("The automatic single-sided router could not connect every part safely.")
    cells = []
    while reached is not None:
        cells.append(reached)
        reached = came[reached]
    cells.reverse()
    points = [start]
    for c in cells[1:-1]:
        p = point(c)
        if len(points) >= 2 and ((points[-1][0] == points[-2][0] == p[0]) or
                                 (points[-1][1] == points[-2][1] == p[1])):
            points[-1] = p
        else:
            points.append(p)
    points.append(point(cells[-1]))
    return points, set(cells)


def _compile_board_once(design, style, enclosure=False, columns=6, route_seed=0):
    components = design["components"]
    if not 1 <= len(components) <= 14:
        raise ValueError("This first version supports projects with 1 to 14 physical parts.")
    smd = style == "surface-mount"
    row_height = 19
    geometry = board_dimensions(len(components), enclosure, columns)
    width, height = geometry["width"], geometry["height"]
    if width > MAX_BOARD_WIDTH or height > MAX_BOARD_HEIGHT:
        raise ValueError("The requested layout exceeds the 100 × 80 mm board limit.")
    positions = {}
    for index, component in enumerate(components):
        kind = component["kind"]
        if kind not in PIN_COUNTS:
            raise ValueError(f"Unsupported part type: {kind}")
        origin = (8 + (index % columns) * 15, 8 + (index // columns) * row_height)
        positions[component["reference"]] = _pad_positions(kind, origin, smd)
    if design.get("layout_shape") == "heart":
        led_components = sorted(
            (component for component in components if component["kind"] == "led"),
            key=lambda component: component["reference"])
        heart_centers = [(34, 16), (64, 16), (76, 30), (68, 48),
                         (49, min(70, height - 12)), (30, 48), (22, 30)]
        if len(led_components) > len(heart_centers):
            raise ValueError("The heart layout supports up to seven LEDs in this version.")
        heart_indices = {
            1: [4], 2: [0, 1], 3: [0, 1, 4], 4: [0, 1, 3, 5],
            5: [0, 1, 2, 4, 6], 6: [0, 1, 2, 3, 4, 6],
            7: [0, 1, 2, 3, 4, 5, 6],
        }
        selected = [heart_centers[index] for index in heart_indices[len(led_components)]]
        for component, (center_x, center_y) in zip(led_components, selected):
            span = 2.0 if smd else 2.54
            positions[component["reference"]] = _pad_positions(
                "led", (center_x - span / 2, center_y), smd)

    endpoint_net = {}
    for net_index, net in enumerate(design["nets"], 1):
        for endpoint in net["endpoints"]:
            if endpoint in endpoint_net:
                raise ValueError(f"Pin {endpoint} was assigned to more than one connection.")
            endpoint_net[endpoint] = net_index
    pads = []
    for component in components:
        ref = component["reference"]
        for pin, point in enumerate(positions[ref], 1):
            endpoint = f"{ref}.{pin}"
            pads.append((endpoint, point, endpoint_net.get(endpoint, 0)))
    known = {item[0] for item in pads}
    for endpoint in endpoint_net:
        if endpoint not in known:
            raise ValueError(f"The circuit refers to a pin that does not exist: {endpoint}")

    step = .5
    mounting_holes = geometry["holes"]
    hole_cells = set()
    for hx, hy in mounting_holes:
        center = (round(hx / step), round(hy / step))
        for dx in range(-5, 6):
            for dy in range(-5, 6):
                if dx * dx + dy * dy <= 25:
                    hole_cells.add((center[0] + dx, center[1] + dy))
    pad_cells = {}
    pad_block_radius = 3 if smd else 4
    for endpoint, point, net_index in pads:
        center = (round(point[0] / step), round(point[1] / step))
        cells = set()
        for dx in range(-pad_block_radius, pad_block_radius + 1):
            for dy in range(-pad_block_radius, pad_block_radius + 1):
                cells.add((center[0] + dx, center[1] + dy))
        pad_cells[endpoint] = cells

    pad_lookup = {endpoint: point for endpoint, point, _net in pads}
    indexed_nets = list(enumerate(design["nets"], 1))
    route_orders = [
        sorted(indexed_nets, key=lambda item: -len(item[1]["endpoints"])),
        sorted(indexed_nets, key=lambda item: len(item[1]["endpoints"])),
        indexed_nets,
        list(reversed(indexed_nets)),
        sorted(indexed_nets, key=lambda item: (len(item[1]["endpoints"]), item[0] % 2)),
    ]
    route_generator = random.Random(route_seed)
    for _ in range(3):
        shuffled = indexed_nets[:]
        route_generator.shuffle(shuffled)
        route_orders.append(shuffled)
    segments = None
    last_route_error = None
    for endpoint_attempt in range(2):
        for nets in route_orders:
            candidate_segments = []
            occupied_by_net = {}
            try:
                for net_index, net in nets:
                    endpoints = list(net["endpoints"])
                    if endpoint_attempt == 1:
                        endpoints.reverse()
                    if len(endpoints) < 2:
                        continue
                    tree_points = [pad_lookup[endpoints[0]]]
                    tree_cells = set(pad_cells[endpoints[0]])
                    for endpoint in endpoints[1:]:
                        start = pad_lookup[endpoint]
                        blocked = set(hole_cells)
                        for other_endpoint, cells in pad_cells.items():
                            if other_endpoint not in endpoints:
                                blocked.update(cells)
                        for other_net, cells in occupied_by_net.items():
                            if other_net != net_index:
                                for cx, cy in cells:
                                    blocked.update((cx + dx, cy + dy) for dx in (-1, 0, 1) for dy in (-1, 0, 1))
                        points, cells = _route(start, tree_points, blocked, width, height, step)
                        candidate_segments.append((net_index, points, "B.Cu"))
                        tree_points.extend(points)
                        tree_cells.update(cells)
                    occupied_by_net[net_index] = tree_cells
                segments = candidate_segments
                break
            except ValueError as error:
                last_route_error = ValueError(
                    f"The automatic single-sided router was blocked while connecting "
                    f"{net.get('name', 'a net')} at {endpoint}.")
        if segments is not None:
            break
    if segments is None:
        # A home-etched board still has only bottom copper, but insulated wire
        # links on the component side can safely bridge otherwise unavoidable
        # crossings. Model those links on F.Cu so KiCad can verify connectivity.
        jumper_vias = []
        for nets in route_orders:
            candidate_segments = []
            occupied_by_layer = {"B.Cu": {}, "F.Cu": {}}
            candidate_vias = []
            virtual_layer_number = 1
            try:
                for net_index, net in nets:
                    endpoints = list(net["endpoints"])
                    if len(endpoints) < 2:
                        continue
                    routed = None
                    for layer in ("B.Cu", "F.Cu"):
                        net_segments = []
                        net_cells = set(pad_cells[endpoints[0]])
                        tree_points = [pad_lookup[endpoints[0]]]
                        try:
                            for endpoint in endpoints[1:]:
                                blocked = set(hole_cells)
                                for other_endpoint, cells in pad_cells.items():
                                    if other_endpoint not in endpoints:
                                        blocked.update(cells)
                                for other_net, cells in occupied_by_layer[layer].items():
                                    if other_net != net_index:
                                        for cx, cy in cells:
                                            blocked.update((cx + dx, cy + dy)
                                                           for dx in (-1, 0, 1)
                                                           for dy in (-1, 0, 1))
                                points, cells = _route(pad_lookup[endpoint], tree_points,
                                                       blocked, width, height, step)
                                net_segments.append((net_index, points, layer))
                                tree_points.extend(points)
                                net_cells.update(cells)
                            routed = (net_segments, net_cells, layer)
                            break
                        except ValueError:
                            continue
                    if routed is None:
                        # Insulated jumper wires may cross each other in the real
                        # build. Give this net a private KiCad guide layer so DRC
                        # validates its endpoints without treating wire crossings
                        # as copper shorts. Only B.Cu is ever exported for etching.
                        layer = f"In{virtual_layer_number}.Cu"
                        virtual_layer_number += 1
                        net_segments = []
                        net_cells = set(pad_cells[endpoints[0]])
                        tree_points = [pad_lookup[endpoints[0]]]
                        for endpoint in endpoints[1:]:
                            blocked = set(hole_cells)
                            points, cells = _route(pad_lookup[endpoint], tree_points,
                                                   blocked, width, height, step)
                            net_segments.append((net_index, points, layer))
                            tree_points.extend(points)
                            net_cells.update(cells)
                        routed = (net_segments, net_cells, layer)
                    net_segments, net_cells, layer = routed
                    candidate_segments.extend(net_segments)
                    occupied_by_layer.setdefault(layer, {})[net_index] = net_cells
                    if smd and layer != "B.Cu":
                        candidate_vias.extend((pad_lookup[endpoint], net_index) for endpoint in endpoints)
                segments = candidate_segments
                jumper_vias = candidate_vias
                break
            except ValueError as error:
                last_route_error = error
        if segments is None:
            raise last_route_error or ValueError("The automatic router could not connect every part safely.")
    else:
        jumper_vias = []

    used_virtual_layers = sorted(
        {layer for _net, _points, layer in segments if layer.startswith("In")},
        key=lambda layer: int(layer[2:].split(".", 1)[0]))
    declared_virtual_layers = used_virtual_layers[:]
    if len(declared_virtual_layers) % 2:
        declared_virtual_layers.append(f"In{len(declared_virtual_layers) + 1}.Cu")
    layer_entries = ['(0 "F.Cu" signal)']
    layer_entries.extend(
        f'({index} "{layer}" signal)'
        for index, layer in enumerate(declared_virtual_layers, 1))
    layer_entries.extend(['(31 "B.Cu" signal)', '(36 "B.SilkS" user "b.silkscreen")',
                          '(44 "Edge.Cuts" user)'])
    lines = ["(kicad_pcb (version 20240108) (generator pcb-laser)",
             "  (general (thickness 1.6))", "  (paper \"A4\")",
             "  (layers " + " ".join(layer_entries) + ")",
             "  (setup (pad_to_mask_clearance 0))", "  (net 0 \"\")"]
    for index, net in enumerate(design["nets"], 1):
        name = str(net["name"]).replace('"', "'")
        lines.append(f'  (net {index} "{name}")')
    for component in components:
        ref, kind = component["reference"], component["kind"]
        layer = "B.Cu" if smd else "F.Cu"
        lines.append(f'  (footprint "{ref}" (layer "{layer}") (at 0 0)')
        for pin, (x, y) in enumerate(positions[ref], 1):
            net_index = endpoint_net.get(f"{ref}.{pin}", 0)
            net_text = f' (net {net_index} "{str(design["nets"][net_index - 1]["name"]).replace(chr(34), chr(39))}")' if net_index else ""
            if smd:
                pad_width, pad_height = _smd_pad_size(kind)
                lines.append(f'    (pad "{pin}" smd roundrect (at {x:.2f} {y:.2f}) (size {pad_width:.2f} {pad_height:.2f}) (layers "B.Cu" "B.Paste" "B.Mask") (roundrect_rratio 0.2){net_text})')
            else:
                shape = "rect" if pin == 1 else "circle"
                lines.append(f'    (pad "{pin}" thru_hole {shape} (at {x:.2f} {y:.2f}) (size 2.2 2.2) (drill 1) (layers "*.Cu" "*.Mask"){net_text})')
        lines.append("  )")
    for index, (x, y) in enumerate(mounting_holes, 1):
        lines.append(f'  (footprint "H{index}" (layer "F.Cu") (at 0 0)')
        lines.append(f'    (pad "" np_thru_hole circle (at {x:.2f} {y:.2f}) (size 3.2 3.2) (drill 3.2) (layers "*.Cu" "*.Mask"))')
        lines.append("  )")
    seen_vias = set()
    for (x, y), net_index in jumper_vias:
        key = (round(x, 2), round(y, 2), net_index)
        if key in seen_vias:
            continue
        seen_vias.add(key)
        lines.append(f'  (via (at {x:.2f} {y:.2f}) (size 0.8) (drill 0.3) (layers "F.Cu" "B.Cu") (net {net_index}))')
    for net_index, points, layer in segments:
        for start, end in zip(points, points[1:]):
            if start == end:
                continue
            track_width = 0.5 if layer == "B.Cu" else 0.25
            lines.append(f'  (segment (start {start[0]:.2f} {start[1]:.2f}) (end {end[0]:.2f} {end[1]:.2f}) (width {track_width}) (layer "{layer}") (net {net_index}))')
    lines.append(f'  (gr_rect (start 0 0) (end {width} {height}) (stroke (width 0.4) (type default)) (fill none) (layer "Edge.Cuts"))')
    lines.append(")")
    return "\n".join(lines)


def compile_board(design, style, enclosure=False):
    """Try reproducible component placements before declaring a board unroutable."""
    base = list(design["components"])
    degree = {component["reference"]: 0 for component in base}
    for net in design["nets"]:
        weight = max(0, len(net["endpoints"]) - 1)
        for endpoint in net["endpoints"]:
            reference = endpoint.split(".", 1)[0]
            if reference in degree:
                degree[reference] += weight
    candidates = [
        base,
        list(reversed(base)),
        sorted(base, key=lambda component: component["reference"]),
        sorted(base, key=lambda component: -degree[component["reference"]]),
        sorted(base, key=lambda component: degree[component["reference"]]),
    ]
    adjacency = {component["reference"]: {} for component in base}
    by_reference = {component["reference"]: component for component in base}
    for net in design["nets"]:
        references = list(dict.fromkeys(endpoint.split(".", 1)[0]
                                        for endpoint in net["endpoints"]
                                        if endpoint.split(".", 1)[0] in adjacency))
        for left in references:
            for right in references:
                if left != right:
                    adjacency[left][right] = adjacency[left].get(right, 0) + 1
    for start in by_reference:
        order = [start]
        remaining = set(by_reference) - {start}
        while remaining:
            next_reference = max(
                remaining,
                key=lambda reference: (
                    3 * adjacency[order[-1]].get(reference, 0)
                    + sum(adjacency[placed].get(reference, 0) for placed in order),
                    degree[reference], reference))
            order.append(next_reference)
            remaining.remove(next_reference)
        candidates.append([by_reference[reference] for reference in order])
        candidates.append([by_reference[reference] for reference in reversed(order)])
    generator = random.Random(8051596)
    for _ in range(12):
        candidate = base[:]
        generator.shuffle(candidate)
        candidates.append(candidate)
    seen = set()
    last_error = None
    deadline = time.monotonic() + 25
    for candidate_index, components in enumerate(candidates):
        if time.monotonic() > deadline:
            break
        order = tuple(component["reference"] for component in components)
        if order in seen:
            continue
        seen.add(order)
        candidate_design = dict(design)
        candidate_design["components"] = components
        column_choices = (6, 5, 4) if len(base) <= 8 else (4, 5, 6)
        for columns in column_choices:
            try:
                return _compile_board_once(candidate_design, style, enclosure, columns,
                                           route_seed=candidate_index * 10 + columns)
            except ValueError as error:
                last_error = error
    raise last_error or ValueError("The automatic single-sided router could not place and connect every part safely.")


def assembly_svg(design, style, led_colors=None, enclosure=False):
    """Draw a friendly top-view preview from the same deterministic placement."""
    components = design["components"]
    smd = style == "surface-mount"
    columns, row_height = 6, 19
    geometry = board_dimensions(len(components), enclosure)
    width, height = geometry["width"], geometry["height"]
    colors = {"red": "#ef4a45", "yellow": "#f2c94c", "green": "#55c878", "blue": "#4a9df8", "white": "#edf5ff"}
    led_colors = led_colors or ["red"]
    led_index = 0
    drawings = []
    for index, component in enumerate(components):
        kind = component["kind"]
        x, y = 8 + (index % columns) * 15, 8 + (index // columns) * row_height
        ref = html.escape(str(component["reference"]))
        value = html.escape(str(component["value"]))
        pads = _pad_positions(kind, (x, y), smd)
        for px, py in pads:
            drawings.append(f'<circle cx="{px}" cy="{py}" r="1.45" fill="#d9b44a" stroke="#6f5620" stroke-width=".35"/>')
        if kind.startswith("ic"):
            count = PIN_COUNTS[kind]
            body_height = ((count // 2) - 1) * (1.27 if smd else 2.54) + 3
            body_x = x + (1.0 if smd else 1.3)
            body_w = 4.0 if smd else 5.0
            drawings.append(f'<rect x="{body_x}" y="{y - 1.5}" width="{body_w}" height="{body_height}" rx="1" fill="#25282b" stroke="#08090a" stroke-width=".4"/>')
            drawings.append(f'<circle cx="{body_x + 1}" cy="{y + .2}" r=".45" fill="#d9d9d9"/>')
        elif kind in {"resistor", "diode"}:
            body_fill = "#d6c091" if kind == "resistor" else "#303338"
            body_w = 3.0 if smd else 5.0
            body_x = x + (.5 if smd else 1.25)
            drawings.append(f'<line x1="{x}" y1="{y}" x2="{pads[-1][0]}" y2="{pads[-1][1]}" stroke="#8a8d90" stroke-width=".55"/>')
            drawings.append(f'<rect x="{body_x}" y="{y - 1.25}" width="{body_w}" height="2.5" rx=".55" fill="{body_fill}" stroke="#4d4638" stroke-width=".35"/>')
            if kind == "resistor":
                for offset, color in ((.7, "#8a4f29"), (1.35, "#1c1c1c"), (2.0, "#cf3030")):
                    drawings.append(f'<line x1="{body_x + offset}" y1="{y - 1.1}" x2="{body_x + offset}" y2="{y + 1.1}" stroke="{color}" stroke-width=".3"/>')
            else:
                drawings.append(f'<line x1="{body_x + body_w - .7}" y1="{y - 1.1}" x2="{body_x + body_w - .7}" y2="{y + 1.1}" stroke="#d8d8d8" stroke-width=".45"/>')
        elif kind == "led":
            led_fill = colors.get(led_colors[led_index % len(led_colors)], colors["red"])
            led_index += 1
            cx = (pads[0][0] + pads[1][0]) / 2
            drawings.append(f'<circle cx="{cx}" cy="{y}" r="2.25" fill="{led_fill}" fill-opacity=".82" stroke="#506070" stroke-width=".45"/>')
            drawings.append(f'<ellipse cx="{cx - .65}" cy="{y - .7}" rx=".45" ry=".7" fill="#fff" fill-opacity=".7"/>')
        elif kind == "capacitor":
            cx = (pads[0][0] + pads[1][0]) / 2
            drawings.append(f'<circle cx="{cx}" cy="{y}" r="2.2" fill="#244c78" stroke="#172b43" stroke-width=".45"/>')
            drawings.append(f'<path d="M {cx - 1.2} {y - 1.5} L {cx - 1.2} {y + 1.5}" stroke="#e7e7e7" stroke-width=".45"/>')
        elif kind == "transistor":
            drawings.append(f'<path d="M {x} {y + 1.8} Q {x + 2.55} {y - 2.6} {x + 5.1} {y + 1.8} Z" fill="#25282b" stroke="#08090a" stroke-width=".4"/>')
        elif kind == "connector2":
            drawings.append(f'<rect x="{x - 1.7}" y="{y - 2.1}" width="{pads[-1][0] - x + 3.4}" height="4.2" rx=".5" fill="#45925f" stroke="#1e5633" stroke-width=".45"/>')
            for px, py in pads:
                drawings.append(f'<rect x="{px - .8}" y="{py - .8}" width="1.6" height="1.6" fill="#c8c9c5" stroke="#505050" stroke-width=".3"/>')
        elif kind == "switch2":
            drawings.append(f'<rect x="{x - 1}" y="{y - 2.3}" width="{pads[-1][0] - x + 2}" height="4.6" rx=".7" fill="#3b3e42" stroke="#111" stroke-width=".4"/>')
            drawings.append(f'<rect x="{x + 1.1}" y="{y - 3.2}" width="2.2" height="2" rx=".4" fill="#b7b9bb"/>')
        drawings.append(f'<text x="{x}" y="{y + 4.1}" font-size="1.65" font-weight="700" fill="#f5f7e9">{ref}</text>')
        drawings.append(f'<title>{ref}: {value}</title>')
    holes_svg = ""
    if enclosure:
        holes_svg = (f'<circle cx="4.5" cy="4.5" r="1.6" fill="#d7d3bd" stroke="#5a665c" stroke-width=".35"/>'
                     f'<circle cx="{width - 4.5}" cy="4.5" r="1.6" fill="#d7d3bd" stroke="#5a665c" stroke-width=".35"/>'
                     f'<circle cx="4.5" cy="{height - 4.5}" r="1.6" fill="#d7d3bd" stroke="#5a665c" stroke-width=".35"/>'
                     f'<circle cx="{width - 4.5}" cy="{height - 4.5}" r="1.6" fill="#d7d3bd" stroke="#5a665c" stroke-width=".35"/>')
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" width="{width * 3}mm" height="{height * 3}mm" viewBox="0 0 {width} {height}">
  <title>{html.escape(str(design["title"]))} assembled board preview</title>
  <defs><filter id="shadow"><feDropShadow dx="1.2" dy="1.5" stdDeviation="1.2" flood-opacity=".28"/></filter></defs>
  <rect width="{width}" height="{height}" fill="#f3eee3"/>
  <g filter="url(#shadow)"><rect x="2" y="2" width="{width - 4}" height="{height - 4}" rx="2" fill="#287050" stroke="#174532" stroke-width=".8"/>
  {holes_svg}
  {''.join(drawings)}</g>
</svg>'''
