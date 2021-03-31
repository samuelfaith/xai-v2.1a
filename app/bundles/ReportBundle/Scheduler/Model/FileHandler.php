<?php

declare(strict_types=1);

/*
 * @copyright   2019 Mautic Contributors. All rights reserved
 * @author      Mautic
 *
 * @link        http://mautic.org
 *
 * @license     GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
 */

namespace Mautic\ReportBundle\Scheduler\Model;

use Mautic\CoreBundle\Exception\FilePathException;
use Mautic\CoreBundle\Helper\CoreParametersHelper;
use Mautic\CoreBundle\Helper\FilePathResolver;
use Mautic\CoreBundle\Helper\FileProperties;
use Mautic\ReportBundle\Entity\Report;
use Mautic\ReportBundle\Exception\FileTooBigException;

class FileHandler
{
    /**
     * @var FilePathResolver
     */
    private $filePathResolver;

    /**
     * @var FileProperties
     */
    private $fileProperties;

    /**
     * @var CoreParametersHelper
     */
    private $coreParametersHelper;

    public function __construct(
        FilePathResolver $filePathResolver,
        FileProperties $fileProperties,
        CoreParametersHelper $coreParametersHelper
    ) {
        $this->filePathResolver     = $filePathResolver;
        $this->fileProperties       = $fileProperties;
        $this->coreParametersHelper = $coreParametersHelper;
    }

    /**
     * @throws FileInvalidException
     * @throws FileTooBigException
     */
    public function fileCanBeAttached(string $filePath): void
    {
        $fileSize    = $this->fileProperties->getFileSize($filePath);
        $maxFileSize = (int) $this->coreParametersHelper->get('report_export_max_filesize_in_bytes');

        if ($fileSize > $maxFileSize) {
            throw new FileTooBigException("File {$filePath} has {$fileSize} bytes which is more than the limit of {$maxFileSize} bytes.");
        }
    }

    /**
     * Zips the file and returns the path where the zip file was created.
     *
     * @throws FilePathException
     */
    public function zipIt(string $originalFilePath): string
    {
        $zipFilePath = str_replace('.csv', '.zip', $originalFilePath);
        $zipArchive  = new \ZipArchive();

        if (true === $zipArchive->open($zipFilePath, \ZipArchive::OVERWRITE | \ZipArchive::CREATE)) {
            $zipArchive->addFile($originalFilePath, 'report.csv');
            $zipArchive->close();

            return $zipFilePath;
        }

        throw new FilePathException("Could not create zip archive at {$zipFilePath}. {$zipArchive->getStatusString()}");
    }

    public function getPathToCompressedCsvFileForReport(Report $report): string
    {
        $reportDir = $this->coreParametersHelper->get('report_temp_dir');

        return "{$reportDir}/csv_reports/report_{$report->getId()}.zip";
    }

    /**
     * @codeCoverageIgnore as it calls PHP function only.
     */
    public function compressedCsvFileForReportExists(Report $report): bool
    {
        return file_exists($this->getPathToCompressedCsvFileForReport($report));
    }

    public function moveZipToPermanentLocation(Report $report, string $originalPath): void
    {
        $compressedCsvPath = $this->getPathToCompressedCsvFileForReport($report);

        $this->filePathResolver->delete($compressedCsvPath);
        $this->filePathResolver->createDirectory(dirname($compressedCsvPath));
        $this->filePathResolver->move($originalPath, $compressedCsvPath);
    }
}
