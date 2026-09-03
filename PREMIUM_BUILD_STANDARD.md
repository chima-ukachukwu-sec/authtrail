# PREMIUM BUILD STANDARD

This file defines the default product, UI, UX, frontend, backend, and engineering quality bar for this repository.

The goal is to build software that feels intentionally designed, mature, original, maintainable, production-ready, and tailored to the actual product rather than generated from generic AI or starter-template patterns.

## 1. Core Principle

Do not make a design or engineering decision merely because it is common, fast to generate, available by default, or visually fashionable.

Base decisions on:

- user workflow
- information hierarchy
- product personality
- interaction frequency
- accessibility
- responsiveness
- performance
- reliability
- maintainability
- actual product requirements

Function and usability come first. Visual polish should reinforce them.

## 2. Avoid the Generic AI-Built UI Look

Do not automatically use:

- giant centered hero headlines
- purple or blue gradient backgrounds
- glowing gradient orbs
- glassmorphism everywhere
- excessive blur
- excessive shadows
- borders around every element
- cards for every piece of information
- deeply rounded rectangles everywhere
- pill badges everywhere
- gradient text
- repetitive icon + heading + paragraph grids
- three-column feature sections by default
- generic SaaS landing-page sections
- random floating UI cards
- excessive dividers
- decorative dotted backgrounds
- generic abstract SVG decorations
- dashboards composed entirely of bordered cards
- animations on every element
- hover effects with no functional purpose
- excessive whitespace used to fake sophistication
- generic AI-generated marketing copy
- identical spacing between every section
- identical card structures throughout the product
- default shadcn or component-library appearance

Use these techniques only when they fit the product and have a clear purpose.

## 3. Do Not Put Everything in a Box

Not every piece of content needs:

- a border
- a background
- a shadow
- a radius
- a card
- a panel

Prefer typography, spacing, alignment, grouping, contrast, and hierarchy before adding containers.

Cards should represent real conceptual objects or meaningful groupings.

## 4. Build Strong Visual Hierarchy

Users should quickly understand:

- where they are
- what matters most
- what action they should take
- what is secondary
- what is informational
- what is interactive

Use:

- type scale
- font weight
- whitespace
- positioning
- density
- contrast
- grouping
- alignment

Do not rely mainly on borders and colored boxes for hierarchy.

## 5. Typography Must Be Intentional

Define typography deliberately for the product:

- display
- headings
- body
- labels
- metadata
- numeric data
- monospace where appropriate

Avoid:

- oversized text without purpose
- tiny gray labels everywhere
- excessive bold text
- random uppercase text
- inconsistent line height
- overly wide text blocks

Optimize for readability and rhythm.

## 6. Use a Real Spacing System

Create a consistent spacing scale.

Use spacing to communicate relationships:

- related elements sit closer
- separate concepts receive more space
- not every gap should be identical

Avoid arbitrary one-off values unless composition genuinely requires them.

## 7. Restrain the Color System

Prefer:

- one primary accent or brand color
- strong neutrals
- semantic success, warning, and error colors
- limited supporting colors when necessary

Avoid rainbow dashboards unless the data genuinely needs them.

Color should communicate meaning, not compensate for weak hierarchy.

## 8. Give the Product a Distinct Personality

Before designing, decide what the product should feel like.

Examples:

- technical
- editorial
- calm
- authoritative
- industrial
- sophisticated
- playful
- luxurious
- developer-focused
- security-focused
- productivity-focused

Translate that into:

- typography
- spacing
- color
- iconography
- density
- motion
- imagery
- navigation
- geometry
- interaction patterns

Do not use the same visual language for every project.

## 9. Create a Distinctive Design Language

Develop recognizable characteristics for this product.

Possible areas:

- navigation treatment
- typography
- data presentation
- layout
- density
- command surfaces
- interaction patterns
- iconography
- section composition
- subtle visual motifs

Distinctiveness must come from coherent product decisions, not gimmicks.

## 10. Component Libraries Are Infrastructure

You may use:

- Radix
- shadcn/ui
- Headless UI
- Material primitives
- Tailwind
- other mature libraries

But do not let the application look like the library demo.

Customize:

- proportions
- typography
- spacing
- borders
- radii
- states
- composition
- hierarchy
- density

Components are implementation primitives, not the product's identity.

## 11. Design the Whole Application

Think beyond isolated screens.

Define:

- navigation model
- page structure
- command surfaces
- search behavior
- filtering
- settings
- empty states
- loading states
- errors
- confirmations
- keyboard behavior
- mobile behavior
- responsive transitions
- destructive actions
- onboarding
- data density
- information architecture

A polished dashboard alone is not enough.

## 12. Design Real States

Meaningful components should account for relevant states:

- default
- hover
- focus
- active
- selected
- disabled
- loading
- empty
- error
- success
- partial data
- long content
- overflow
- permission denied
- offline when applicable

Do not optimize only for perfect sample data.

## 13. Use Realistic Product-Specific Copy

Avoid lazy placeholder copy such as:

- "Boost your productivity with AI"
- "Unlock the power of automation"
- "Transform your workflow"

Use concise, contextual, product-specific language.

## 14. Motion Must Have a Purpose

Animation should communicate:

- change
- hierarchy
- continuity
- state transitions
- cause and effect

Prefer subtle motion.

Respect `prefers-reduced-motion`.

Do not animate everything on load.

## 15. Responsive Design Is Intentional

Design for:

- large desktop
- laptop
- tablet
- mobile

Decide deliberately:

- what collapses
- what disappears
- what becomes a drawer
- what scrolls horizontally
- what retains density
- how navigation changes

Do not solve responsiveness by stacking every desktop element vertically.

## 16. Accessibility Is Part of Premium Quality

Implement:

- semantic HTML
- keyboard navigation
- logical focus order
- visible focus states
- sufficient contrast
- accessible labels
- appropriate ARIA
- reduced-motion support
- usable touch targets
- screen-reader-friendly controls

Do not sacrifice usability for visual minimalism.

## 17. Performance Is Part of Product Quality

Avoid:

- unnecessarily large dependencies
- oversized JavaScript bundles
- giant background videos
- unoptimized images
- unnecessary client-side rendering
- expensive animations
- layout shift

Prioritize:

- fast initial rendering
- responsive interactions
- image optimization
- sensible code splitting
- efficient data loading

Premium software should feel fast.

## 18. Build Workflow Depth Before Decoration

Prioritize engineering effort on:

1. faster workflows
2. better information architecture
3. smarter defaults
4. keyboard shortcuts
5. command palettes
6. useful automation
7. contextual actions
8. excellent search
9. useful filtering
10. state preservation
11. undo and recovery
12. polished interactions

Spend less effort on decorative effects that do not improve the workflow.

## 19. Benchmark Principles, Do Not Clone Products

Study the discipline found in strong products such as:

- Linear
- Stripe
- Vercel
- Raycast
- Arc
- Notion
- Figma
- GitHub
- Framer
- Superhuman
- Apple
- Things
- Craft

Do not copy their UI.

Study:

- restraint
- hierarchy
- consistency
- responsiveness
- typography
- interaction quality
- workflow optimization
- information density
- attention to detail

Create an original implementation appropriate to this product.

## 20. Preserve Good Existing Decisions

When working in an existing project, inspect:

- design system
- components
- typography
- colors
- spacing
- layout conventions
- interaction patterns
- accessibility behavior

Keep what works.

Improve weak areas deliberately.

Do not cause visual churn without a reason.

## 21. Backend and Architecture Anti-Patterns

AI-generated projects often reveal themselves through needless complexity.

Avoid by default:

- abstractions with no demonstrated need
- interfaces with only one implementation
- premature factories
- generic `utils` modules that become dumping grounds
- unnecessary service or repository layers
- excessive dependency injection
- placeholder architecture for hypothetical scale
- too many tiny files
- needless wrapper functions
- comments explaining obvious code
- fake enterprise architecture
- excessive configuration
- duplicate validation logic
- hidden side effects
- premature microservices
- unnecessary event buses
- abstractions created only to make code look sophisticated

Use the simplest architecture that cleanly satisfies current requirements and leaves expensive-to-change boundaries well designed.

## 22. Code Quality Standard

Prefer:

- clear naming
- small cohesive modules
- explicit data flow
- strong types where useful
- predictable error handling
- useful validation
- stable interfaces at real boundaries
- tests focused on behavior
- minimal dependencies
- secure defaults
- observability where operationally useful

No complexity without a concrete reason.

No abstraction without a demonstrated need.

## 23. Before Implementation

Before writing substantial UI or architecture code, determine:

### Product
- Who is using this?
- What are they trying to accomplish?
- What are the highest-frequency workflows?

### Information architecture
- What belongs on this screen?
- What is primary?
- What is secondary?
- What can be progressively disclosed?

### Visual direction
Choose an intentional visual direction appropriate to this product.

### Interaction model
Identify:

- primary action
- secondary actions
- navigation
- keyboard opportunities
- context menus
- shortcuts
- progressive disclosure

### Architecture
Identify:

- stable boundaries
- data ownership
- security boundaries
- persistence needs
- external integrations
- failure modes
- test strategy

Then implement.

Do not produce lengthy speculative design or architecture documents unless requested.

## 24. Post-Implementation Audit

Before declaring work complete, audit the result.

### AI-Look Audit
Check for:

- too many cards
- too many borders
- too many rounded rectangles
- excessive gradients
- repetitive layout structures
- generic hero composition
- generic copy
- excessive icons
- excessive badges
- decorative noise
- excessive empty space
- default library appearance
- inconsistent hierarchy

If the interface looks generated, refine it.

### Product Audit
Can the user complete important workflows quickly?

### Visual Audit
Is hierarchy obvious?

### Consistency Audit
Are typography, spacing, states, and interactions coherent?

### Accessibility Audit
Can the interface be used by keyboard and assistive technologies?

### Responsive Audit
Does it behave intentionally across screen sizes?

### Performance Audit
Did the implementation introduce unnecessary weight or complexity?

### Engineering Audit
Check for:

- unnecessary abstraction
- duplication
- hidden coupling
- weak error handling
- missing edge-case tests
- insecure defaults
- dead code
- excessive dependencies
- fake extensibility
- inconsistent naming

Fix issues discovered before stopping.

## 25. Quality Bar

Do not stop when "it works."

Stop when:

- it works
- it is coherent
- important edge cases are handled
- it is responsive
- it is accessible
- interactions feel polished
- typography is deliberate
- hierarchy is clear
- the interface feels original
- unnecessary decoration has been removed
- obvious AI-generated patterns are gone
- code remains understandable and maintainable
- tests cover meaningful behavior
- security and failure modes have been considered

Premium does not mean more gradients, animation, glass, cards, shadows, components, whitespace, or abstraction.

Premium means thoughtful, restrained, fast, clear, consistent, useful, distinctive, reliable, and polished.

When uncertain, remove rather than add.

Build the smallest amount of visual and architectural structure required to create the strongest product.
