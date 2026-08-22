<?php

/**
 * Reglas de formato del proyecto. Ver docs/guia-de-estilo.md
 *
 *   composer estilo           comprueba sin tocar nada (lo que hace la CI)
 *   composer estilo:aplicar   reescribe los ficheros
 *
 * IMPORTANTE — este repositorio parte de código procedural escrito con
 * tabuladores y sin tipado estricto. La primera ejecución de `estilo:aplicar`
 * reformatea prácticamente todos los ficheros PHP: hazla en un PR propio de
 * tipo `style:`, sin mezclarla con ningún cambio funcional, para que el diff
 * sea revisable.
 *
 * Por eso la regla `declare_strict_types` está DESACTIVADA aquí: activarla en
 * masa sí cambia el comportamiento en tiempo de ejecución (PHP deja de
 * convertir tipos entre int, float y string) y este código no tiene pruebas
 * que lo respalden. Se activa fichero a fichero, a mano, según se vayan
 * migrando. Ver el TODO más abajo.
 */

$finder = PhpCsFixer\Finder::create()
    ->in([
        __DIR__ . '/api_server',
        __DIR__ . '/app',
        __DIR__ . '/libs',
        __DIR__ . '/public',
    ])
    ->append([__FILE__])
    // liboqs-php es un submódulo de terceros; el resto son dependencias y stubs.
    ->exclude(['vendor', 'node_modules', 'dist', 'liboqs-php', 'stubs']);

return (new PhpCsFixer\Config())
    ->setRiskyAllowed(true)
    ->setFinder($finder)
    ->setCacheFile(__DIR__ . '/.php-cs-fixer.cache')
    ->setRules([
        '@PSR12' => true,
        '@PSR12:risky' => true,

        // TODO(#-): activar cuando todos los ficheros de api_server/, app/ y
        // libs/ estén tipados. Hasta entonces se pone a mano, fichero a fichero.
        'declare_strict_types' => false,

        // Importaciones ordenadas y sin sobrantes.
        'ordered_imports' => ['sort_algorithm' => 'alpha'],
        'no_unused_imports' => true,

        // Arrays y llamadas: sintaxis corta y coma final en multilínea.
        'array_syntax' => ['syntax' => 'short'],
        'trailing_comma_in_multiline' => [
            'elements' => ['arrays', 'arguments', 'parameters', 'match'],
        ],
        'whitespace_after_comma_in_array' => true,

        // Comparaciones estrictas: crítico en código criptográfico.
        // Es una regla risky: revisa el diff de la primera pasada con atención.
        'strict_comparison' => true,
        'strict_param' => true,

        // Legibilidad
        'single_quote' => true,
        'concat_space' => ['spacing' => 'one'],
        'no_superfluous_elseif' => true,
        'no_useless_else' => true,
        'no_useless_return' => true,
        'simplified_null_return' => true,
        'blank_line_before_statement' => [
            'statements' => ['return', 'throw', 'try'],
        ],

        // PHPDoc
        'no_empty_phpdoc' => true,
        'phpdoc_align' => ['align' => 'left'],
        'phpdoc_indent' => true,
        'phpdoc_order' => true,
        'phpdoc_separation' => true,
        'phpdoc_trim' => true,

        // Clases
        'self_accessor' => true,
        'single_class_element_per_statement' => true,
        'visibility_required' => ['elements' => ['property', 'method', 'const']],

        // Higiene
        'no_alias_functions' => true,
        'native_function_invocation' => false,
        'linebreak_after_opening_tag' => true,
        'no_trailing_whitespace_in_comment' => true,
        // El código actual usa `#` para comentar; PSR-12 pide `//`.
        'single_line_comment_style' => ['comment_types' => ['hash']],
    ]);
